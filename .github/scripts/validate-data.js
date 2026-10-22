// Validates data/<year>/CVE-<year>-<id>.json files against schemas/vulnrichment.schema.json
// and checks that every commit changes one data file with a matching message.
// Usage: node .github/scripts/validate-data.js [baseRef] [headRef]
//   with refs: files and commits added since baseRef, e.g. origin/main <pr head sha>
//   without:   every file under data/, no commit checks
const fs = require('fs');
const { execFileSync } = require('child_process');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const FILE_PATH = /^data\/(\d{4})\/(CVE-(\d{4})-\d{4,})\.json$/;
const ACTIONS = { A: 'add', M: 'modify', D: 'delete' };

// strictTypes off so metrics can extend the shared cvssMetric definition;
// strictRequired off so a node can require cpeMatch or children inside anyOf
const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false });
addFormats(ajv);
const validateSchema = ajv.compile(JSON.parse(fs.readFileSync('schemas/vulnrichment.schema.json', 'utf8')));

const [baseRef, headRef = 'HEAD'] = process.argv.slice(2);
const files = baseRef
    ? lines(git('diff', '--name-only', '--no-renames', '--diff-filter=AM', `${baseRef}...${headRef}`, '--', 'data/'))
    : lines(git('ls-files', 'data/'));
const commits = baseRef ? lines(git('rev-list', '--no-merges', '--reverse', `${baseRef}..${headRef}`)) : [];

let errorCount = 0;
files.forEach(file => validateFile(file).forEach(message => report(file, message)));
commits.forEach(sha => validateCommit(sha).forEach(message => report(null, message)));

console.log(`Validated ${files.length} file(s) and ${commits.length} commit(s): ${errorCount} error(s) found.`);
process.exit(errorCount ? 1 : 0);

function validateFile(file) {
    const match = file.match(FILE_PATH);
    if (!match) return [`Invalid path: "${file}" must follow the format data/<year>/CVE-<year>-<id>.json.`];
    const [, folderYear, cveId, cveYear] = match;
    if (folderYear !== cveYear) return [`Invalid location: ${cveId} belongs in data/${cveYear}, not data/${folderYear}.`];

    let record;
    try {
        record = JSON.parse(baseRef ? git('show', `${headRef}:${file}`) : fs.readFileSync(file, 'utf8'));
    } catch (err) {
        return [`Invalid JSON: the file could not be parsed (${err.message}).`];
    }

    const errors = validateSchema(record) ? [] : validateSchema.errors.map(formatSchemaError);
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
    // Without rename detection a rename shows up as a delete plus an add, i.e. two files
    const changes = lines(git('diff-tree', '--no-commit-id', '-r', '--no-renames', '--name-status', sha)).map(line => line.split('\t'));
    if (!changes.some(([, file]) => file.startsWith('data/'))) return [];

    const prefix = `Commit ${sha.slice(0, 7)} ("${subject}")`;
    if (changes.length !== 1) {
        return [`${prefix} changes ${changes.length} files. Each commit must add, modify or delete exactly one file; renames must be split into a delete commit and an add commit.`];
    }

    const [status, file] = changes[0];
    const expected = `${ACTIONS[status]} ${file.split('/').pop().replace(/\.[^.]*$/, '')}`;
    return subject === expected ? [] : [`${prefix} changes ${file}. The message must be "${expected}".`];
}

function report(file, message) {
    errorCount++;
    console.log(file ? `::error file=${file}::${message}` : `::error::${message}`);
}

function lines(text) {
    return text.split('\n').filter(Boolean);
}

function git(...args) {
    return execFileSync('git', args, { encoding: 'utf8' });
}
