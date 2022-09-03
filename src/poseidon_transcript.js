import { Poseidon } from "poseidon-js";
import { utils } from "ffjavascript";
export class Transcript {
	constructor(hasherSpecPath, curve) {
		this.hasherSpecPath = hasherSpecPath;
		this.curve = curve;
		this.Fr = curve.Fr;
		this.F1 = curve.F1;
		this.G1 = curve.G1;

		// hasher
		this.poseidon = new Poseidon(hasherSpecPath, this.curve);
	}

	async load() {
		await this.poseidon.parseSpec();
		this.poseidon.loadState();
	}

	// Scalar is a Field element in field Fr
	writeScalar(scalar, tag) {
		console.log(`Writing scalar ${tag}: ${this.Fr.toString(scalar, 16)}`);
		this.poseidon.update([scalar]);
	}

	// Point in on curve G1
	writePoint(point, tag) {
		let [x, y] = [this.G1.x(point), this.G1.y(point)].map((v) => {
			let modFr = BigInt(
				"21888242871839275222246405745257275088548364400416034343698204186575808495617"
			);

			v = BigInt(this.F1.toString(v, 10));
			v = v % modFr;
			return this.Fr.fromRprLE(utils.leInt2Buff(v));
		});

		// console.log(`Writing point ${tag}: x=${x}, y=${y}`);
		this.poseidon.update([x, y]);
	}

	// squeeze challenge
	squeezeChallenge() {
		return this.poseidon.squeeze();
	}
}
