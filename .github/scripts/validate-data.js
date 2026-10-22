// Validates data/<year>/CVE-<year>-<id>.json files against schemas/vulnrichment.schema.json
// Usage: node .github/scripts/validate-data.js [baseRef]
//   with baseRef: only files added/changed since baseRef, e.g. origin/main
//   without:      every file under data/
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');

const DATA_DIR = 'data';
const SCHEMA_PATH = path.join('schemas', 'vulnrichment.schema.json');
const FILE_NAME = /^CVE-(\d{4})-\d{4,}\.json$/;

// strictRequired off so a node can require cpeMatch or children inside anyOf
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validate = ajv.compile(JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8')));

const baseRef = process.argv[2];
const files = baseRef ? changedFiles(baseRef) : allFiles(DATA_DIR);

let errorCount = 0;
files.forEach(file => validateFile(file).forEach(message => {
    errorCount++;
    console.log(`::error file=${file}::${message}`);
}));

console.log(`Checked ${files.length} file(s), ${errorCount} error(s)`);
process.exit(errorCount ? 1 : 0);

function validateFile(file) {
    const [dir, year, name, ...rest] = file.split('/');
    if (dir !== DATA_DIR || !name || rest.length) return [`must be at ${DATA_DIR}/<year>/CVE-<year>-<id>.json`];
    if (!name.endsWith('.json')) return ['file name must end with .json'];

    const match = name.match(FILE_NAME);
    if (!match) return ['file name must be CVE-<year>-<id>.json'];
    if (match[1] !== year) return [`CVE year ${match[1]} does not match folder ${DATA_DIR}/${year}`];

    let record;
    try {
        record = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
        return [`invalid JSON: ${err.message}`];
    }

    const errors = [];
    if (!validate(record)) {
        validate.errors.forEach(err => errors.push(`${err.instancePath || '/'} ${err.message}${err.params?.additionalProperty ? ` '${err.params.additionalProperty}'` : ''}`));
    }

    const cveId = name.replace('.json', '');
    if (record?._annotation?.cve_id && record._annotation.cve_id !== cveId) {
        errors.push(`/_annotation/cve_id ${record._annotation.cve_id} does not match file name ${cveId}`);
    }
    return errors;
}

function changedFiles(ref) {
    const output = execFileSync('git', ['diff', '--name-only', '-z', '--diff-filter=AMR', `${ref}...HEAD`, '--', `${DATA_DIR}/`], { encoding: 'utf8' });
    return output.split('\0').filter(Boolean);
}

function allFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const entryPath = `${dir}/${entry.name}`;
        return entry.isDirectory() ? allFiles(entryPath) : [entryPath];
    });
}
