// Resolve the Circom-generated witness writer for the selected relation.
const path = require("node:path");
require(path.join(path.dirname(process.argv[2]), "generate_witness.js"));
