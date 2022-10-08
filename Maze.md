# Using Snarkjs with Maze

This fork of snarkjs helps you use snarkjs with Maze. To do that the fork implements the following additions/changes: 
1. Adds necessary cli commands / functions for using snarkjs with Maze.
2. Replaces hash function from `keccak` to `poseidon` in transcript used for generating plonk proofs for circom circuits. Poseidon spec file is here. 


### Install the fork

Note: Installing this fork will override your existing installation of snarkjs.

To install this fork locally:
1. Clone this fork.
2. Cd into the directory.
3. run:
    ```sh
        > npm install
        > npm run build
        > npm run buildcli
        > npm install -g .
    ```

Rest of the installation procedure remains same as of snarkjs.

## Guide
Necessary files for using maze to aggregate a pre-decided number of plonk-proofs of a circom circuit are the inputs files and the verification key of the plonk circuit converted from the original circom circuit. Following steps show how to generate them easily. 

Throughout this we will often refer to original guide as original 