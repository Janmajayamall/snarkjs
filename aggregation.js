import fs from "fs";
import * as zkey from "./src/zkey.js";
import * as plonk from "./src/plonk.js";
import * as powersOfTau from "./src/powersoftau.js";
import * as curves from "./src/curves.js";
import bfj from "bfj";
import { utils } from "ffjavascript";
const { stringifyBigInts } = utils;

import Logger from "logplease";
const logger = Logger.create("snarkJS", { showTimestamp: false });
Logger.setLogLevel("DEBUG");

let SKIP_TAU = true;

async function main() {
	let filePath = `${process.cwd()}/tmp/`;
	let curve = await curves.getCurveFromName("bn128");

	if (!SKIP_TAU) {
		await powersOfTau.newAccumulator(
			curve,
			12,
			`${filePath}pot12_000.ptau`,
			logger
		);
		await powersOfTau.contribute(
			`${filePath}pot12_000.ptau`,
			`${filePath}pot12_001.ptau`,
			"First contribution",
			"something",
			logger
		);

		await powersOfTau.verify(`${filePath}pot12_001.ptau`, logger);
		await powersOfTau.beacon(
			`${filePath}pot12_001.ptau`,
			`${filePath}pot12_beacon.ptau`,
			"final beacon",
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			10,
			logger
		);

		await powersOfTau.preparePhase2(
			`${filePath}pot12_beacon.ptau`,
			`${filePath}pot12_final.ptau`,
			logger
		);
		await powersOfTau.verify(`${filePath}pot12_final.ptau`, logger);
	}

	// Make sure you have circuit.circom inside /tmp. Generate rest of files using
	// `circom circuit.circom --r1cs --wasm --sym`

	// plonk setup
	await plonk.setup(
		`${filePath}circuit.r1cs`,
		`${filePath}pot12_final.ptau`,
		`${filePath}circuit_final.zkey`,
		logger
	);

	// export verification key
	let vKey = await zkey.exportVerificationKey(
		`${filePath}circuit_final.zkey`
	);
	await bfj.write(
		`${filePath}verification_key.json`,
		stringifyBigInts(vKey),
		{
			space: 1,
		}
	);

	// create full proof
	const input = JSON.parse(
		await fs.promises.readFile(`${filePath}input.json`, "utf8")
	);
	let { proof, publicSignals } = await plonk.fullProve(
		input,
		`${filePath}circuit.wasm`,
		`${filePath}circuit_final.zkey`,
		logger
	);
	await bfj.write(`${filePath}proof.json`, stringifyBigInts(proof), {
		space: 1,
	});
	await bfj.write(`${filePath}public.json`, stringifyBigInts(publicSignals), {
		space: 1,
	});

	// verify proof
	vKey = JSON.parse(
		fs.readFileSync(`${filePath}verification_key.json`, "utf8")
	);
	publicSignals = JSON.parse(
		fs.readFileSync(`${filePath}public.json`, "utf8")
	);
	proof = JSON.parse(fs.readFileSync(`${filePath}proof.json`, "utf8"));
	const isValid = await plonk.verify(vKey, publicSignals, proof, logger);
	console.log("IsValid:", isValid);
}

async function verifyOnly() {
	let filePath = `${process.cwd()}/tmp/`;
	let curve = await curves.getCurveFromName("bn128");

	// verify proof
	let vKey = JSON.parse(
		fs.readFileSync(`${filePath}verification_key.json`, "utf8")
	);
	let publicSignals = JSON.parse(
		fs.readFileSync(`${filePath}public.json`, "utf8")
	);
	let proof = JSON.parse(fs.readFileSync(`${filePath}proof.json`, "utf8"));
	const isValid = await plonk.verify(vKey, publicSignals, proof, logger);
	console.log("IsValid:", isValid);
}

main()
	.then(() => {
		process.exit();
	})
	.catch((e) => {
		console.log("Error: ", e);
		process.exit();
	});

// verifyOnly()
// 	.then(() => {
// 		process.exit();
// 	})
// 	.catch((e) => {
// 		console.log("Error: ", e);
// 		process.exit();
// 	});
