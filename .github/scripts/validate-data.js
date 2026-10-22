// Validates data/<year>/CVE-<year>-<id>.json files against schemas/vulnrichment.schema.json
// and checks that every commit changes one data file with a matching message.
// Usage: node .github/scripts/validate-data.js [baseRef] [headRef]
//   with refs: files and commits added since baseRef, e.g. <base sha> <pr head sha>
//   without:   every tracked file under data/, no commit checks
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const addErrors = require('ajv-errors');

const FILE_PATH = /^data\/(\d{4})\/(CVE-(\d{4})-\d{4,})\.json$/;
const ACTIONS = { A: 'add', M: 'modify', D: 'delete' };

process.chdir(path.join(__dirname, '..', '..'));

// strictTypes off so metrics can extend the shared cvssMetric definition;
// strictRequired off so a node can require cpeMatch or children inside anyOf
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false });
addFormats(ajv);
addErrors(ajv); // replaces anyOf/not noise with the schema's errorMessage text
const validateSchema = ajv.compile(JSON.parse(fs.readFileSync('schemas/vulnrichment.schema.json', 'utf8')));

let errorCount = 0;
try {
    run(process.argv.slice(2));
} catch (err) {
    report(null, `The validator could not run: ${err.message.trim()}`);
}
process.exitCode = errorCount ? 1 : 0;

function run([baseRef, headRef]) {
    if (baseRef && !headRef) throw new Error('both a base ref and a head ref are required.');
    const base = baseRef && resolve(baseRef);
    const head = headRef && resolve(headRef);
    if (base && git('rev-parse', '--is-shallow-repository').trim() === 'true') {
        throw new Error('the repository is a shallow clone; check it out with fetch-depth: 0.');
    }

    const files = base
        ? split(git('diff', '--name-only', '-z', '--no-renames', '--diff-filter=AM', `${base}...${head}`, '--', 'data/'))
        : split(git('ls-files', '-z', '--', 'data/'));
    const commits = base ? split(git('rev-list', '--reverse', `${base}..${head}`), '\n') : [];

    const read = file => (base ? git('show', `${head}:${file}`) : fs.readFileSync(file, 'utf8'));
    files.forEach(file => validateFile(file, read).forEach(message => report(file, message)));
    commits.forEach(sha => validateCommit(sha).forEach(message => report(null, message)));

    console.log(`Validated ${files.length} file(s) and ${commits.length} commit(s): ${errorCount} error(s) found.`);
}

function validateFile(file, read) {
    const match = file.match(FILE_PATH);
    if (!match) return [`Invalid path: "${file}" must follow the format data/<year>/CVE-<year>-<id>.json.`];
    const [, folderYear, cveId, cveYear] = match;
    if (folderYear !== cveYear) return [`Invalid location: ${cveId} belongs in data/${cveYear}, not data/${folderYear}.`];

    let record;
    try {
        record = JSON.parse(read(file));
    } catch (err) {
        return [`Invalid JSON: the file could not be parsed (${err.message}).`];
    }

    // Errors from inside anyOf branches are summarised by the anyOf error itself
    const errors = validateSchema(record) ? [] : validateSchema.errors
        .filter(err => !err.schemaPath.includes('/anyOf/'))
        .map(formatSchemaError);
    const annotatedId = record?._annotation?.cve_id;
    if (annotatedId && annotatedId !== cveId) {
        errors.push(`Identifier mismatch: _annotation.cve_id is "${annotatedId}", but the file name requires "${cveId}".`);
    }
    return errors;
}

function formatSchemaError(err) {
    const extra = err.params.additionalProperty ?? err.params.allowedValues?.join(', ') ?? err.params.allowedValue;
    return `Schema violation at ${err.instancePath || '/'}: ${err.message}${extra === undefined ? '' : ` (${extra})`}.`;
}

function validateCommit(sha) {
    const subject = git('log', '-1', '--format=%s', sha).trim();
    const prefix = `Commit ${sha.slice(0, 7)} ("${subject}")`;
    const isMerge = split(git('rev-list', '--parents', '-n', '1', sha), ' ').length > 2;

    // A merge may only combine its parents; data changes of its own would bypass the rules below
    if (isMerge) {
        const own = split(git('diff-tree', '--cc', '--name-only', '--no-commit-id', '-z', sha)).filter(file => file.startsWith('data/'));
        return own.length ? [`${prefix} is a merge that changes ${own.join(', ')} itself. Make data changes in regular commits.`] : [];
    }

    // -z output alternates status and path; without rename detection a rename is a delete plus an add
    const fields = split(git('diff-tree', '-r', '--no-commit-id', '--no-renames', '--name-status', '-z', sha));
    const changes = [];
    for (let i = 0; i < fields.length; i += 2) changes.push({ status: fields[i], file: fields[i + 1] });
    if (!changes.some(({ file }) => file.startsWith('data/'))) return [];

    if (changes.length !== 1) {
        return [`${prefix} changes ${changes.length} files. Each commit must add, modify or delete exactly one file; renames must be split into a delete commit and an add commit.`];
    }

    const { status, file } = changes[0];
    if (!ACTIONS[status]) return [`${prefix} changes ${file} with git status ${status}. Only adding, modifying and deleting files is permitted.`];
    const expected = `${ACTIONS[status]} ${path.posix.basename(file).replace(/\.[^.]*$/, '')}`;
    return subject === expected ? [] : [`${prefix} changes ${file}. The message must be "${expected}".`];
}

// Escaped so that file contents and commit subjects cannot inject workflow commands
function report(file, message) {
    errorCount++;
    const data = text => text.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    const property = text => data(text).replace(/:/g, '%3A').replace(/,/g, '%2C');
    console.log(file ? `::error file=${property(file)}::${data(message)}` : `::error::${data(message)}`);
}

function resolve(ref) {
    if (ref.startsWith('-')) throw new Error(`"${ref}" is not a valid ref.`);
    return git('rev-parse', '--verify', '--quiet', `${ref}^{commit}`).trim();
}

function split(text, separator = '\0') {
    return (separator === '\0' ? text : text.trim()).split(separator).filter(Boolean);
}

function git(...args) {
    return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1024 ** 3, stdio: ['ignore', 'pipe', 'pipe'] });
}
