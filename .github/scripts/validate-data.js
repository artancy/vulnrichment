// Validates data/<year>/CVE-<year>-<id>.json files against schemas/vulnrichment.schema.json
// and checks that every commit changes one data file with a matching message.
// Usage: node .github/scripts/validate-data.js [baseRef] [headRef]
//   with refs: files and commits added since baseRef, e.g. origin/main <pr head sha>
//   without:   every file under data/, no commit checks
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const DATA_DIR = 'data';
const SCHEMA_PATH = path.join('schemas', 'vulnrichment.schema.json');
const FILE_NAME = /^CVE-(\d{4})-\d{4,}\.json$/;
const COMMIT_MESSAGE = /^(add|modify|delete) (CVE-\d{4}-\d{4,})$/;
const COMMIT_ACTIONS = { A: 'add', M: 'modify', D: 'delete' };

// strictRequired off so a node can require cpeMatch or children inside anyOf
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validate = ajv.compile(JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8')));

const [baseRef, headRef = 'HEAD'] = process.argv.slice(2);
const files = baseRef ? changedFiles(baseRef, headRef) : allFiles(DATA_DIR);
const commits = baseRef ? prCommits(baseRef, headRef) : [];

let errorCount = 0;
files.forEach(file => validateFile(file).forEach(message => report(message, file)));
commits.forEach(sha => validateCommit(sha).forEach(error => report(error.message, error.file)));

console.log(`Validated ${files.length} file(s) and ${commits.length} commit(s): ${errorCount} error(s) found.`);
process.exit(errorCount ? 1 : 0);

function report(message, file) {
    errorCount++;
    console.log(file ? `::error file=${file}::${message}` : `::error::${message}`);
}

function validateFile(file) {
    const [dir, year, name, ...rest] = file.split('/');
    if (dir !== DATA_DIR || !name || rest.length) return [`Invalid location: files must be placed at ${DATA_DIR}/<year>/CVE-<year>-<id>.json.`];
    if (!name.endsWith('.json')) return [`Invalid file extension: "${name}" must use the .json extension.`];

    const match = name.match(FILE_NAME);
    if (!match) return [`Invalid file name: "${name}" does not follow the required format CVE-<year>-<id>.json.`];
    if (match[1] !== year) return [`Invalid location: ${match[0].replace('.json', '')} belongs in ${DATA_DIR}/${match[1]}, not ${DATA_DIR}/${year}.`];

    let record;
    try {
        record = JSON.parse(baseRef ? git('show', `${headRef}:${file}`) : fs.readFileSync(file, 'utf8'));
    } catch (err) {
        return [`Invalid JSON: the file could not be parsed (${err.message}).`];
    }

    const errors = [];
    if (!validate(record)) {
        validate.errors.forEach(err => errors.push(formatSchemaError(err)));
    }

    const cveId = name.replace('.json', '');
    if (record?._annotation?.cve_id && record._annotation.cve_id !== cveId) {
        errors.push(`Identifier mismatch: _annotation.cve_id is "${record._annotation.cve_id}", but the file name requires "${cveId}".`);
    }
    return errors;
}

function formatSchemaError(err) {
    const location = err.instancePath || '/';
    if (err.keyword === 'additionalProperties') return `Schema violation at ${location}: property "${err.params.additionalProperty}" is not permitted.`;
    if (err.keyword === 'required') return `Schema violation at ${location}: required property "${err.params.missingProperty}" is missing.`;
    if (err.keyword === 'enum') return `Schema violation at ${location}: value must be one of ${err.params.allowedValues.map(v => `"${v}"`).join(', ')}.`;
    return `Schema violation at ${location}: value ${err.message}.`;
}

function validateCommit(sha) {
    const shortSha = sha.slice(0, 7);
    const subject = git('log', '-1', '--format=%s', sha).trim();
    const changes = git('diff-tree', '--no-commit-id', '-r', '-M', '--name-status', '-z', sha).split('\0').filter(Boolean);

    // Entries come as status, path (and a second path for renames)
    const entries = [];
    for (let i = 0; i < changes.length;) {
        const status = changes[i++];
        const paths = status.startsWith('R') || status.startsWith('C') ? [changes[i++], changes[i++]] : [changes[i++]];
        entries.push({ status: status[0], paths });
    }

    // Commits that do not touch data/ are not subject to these rules
    if (!entries.some(entry => entry.paths.some(p => p.startsWith(`${DATA_DIR}/`)))) return [];

    if (entries.length !== 1) {
        return [{ message: `Commit ${shortSha} ("${subject}") changes ${entries.length} files. Each commit must add, modify or delete exactly one file.` }];
    }

    const { status, paths } = entries[0];
    const file = paths[paths.length - 1];
    if (status === 'R') {
        return [{ file, message: `Commit ${shortSha} renames ${paths[0]} to ${paths[1]}. Renames are not permitted; delete the file in one commit and add it in a separate commit.` }];
    }

    const action = COMMIT_ACTIONS[status];
    if (!action) return [{ file, message: `Commit ${shortSha} performs an unsupported change (${status}) on ${file}. Only add, modify and delete are permitted.` }];

    const cveId = path.basename(file).split('.')[0];
    const expected = `${action} ${cveId}`;
    const match = subject.match(COMMIT_MESSAGE);
    if (!match) return [{ file, message: `Commit ${shortSha} has the message "${subject}". The required format is "<add|modify|delete> CVE-<year>-<id>"; expected "${expected}".` }];

    const errors = [];
    if (match[1] !== action) errors.push({ file, message: `Commit ${shortSha} is described as "${match[1]}", but the file was ${action === 'modify' ? 'modified' : `${action}ed`}. Expected message: "${expected}".` });
    if (match[2] !== cveId) errors.push({ file, message: `Commit ${shortSha} references ${match[2]}, but changes ${path.basename(file)}. Expected message: "${expected}".` });
    return errors;
}

function changedFiles(base, head) {
    return git('diff', '--name-only', '-z', '--diff-filter=AMR', `${base}...${head}`, '--', `${DATA_DIR}/`).split('\0').filter(Boolean);
}

function prCommits(base, head) {
    return git('rev-list', '--no-merges', '--reverse', `${base}..${head}`).split('\n').filter(Boolean);
}

function allFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const entryPath = `${dir}/${entry.name}`;
        return entry.isDirectory() ? allFiles(entryPath) : [entryPath];
    });
}

function git(...args) {
    return execFileSync('git', args, { encoding: 'utf8' });
}
