import { Poseidon } from "poseidon-js";

export class Transcript {
	constructor(hasherSpecPath, curve) {
		this.hasherSpecPath = hasherSpecPath;
		this.curve = curve;
		this.Fr = curve.Fr;
		this.G1 = curve.G1;

		// hasher
		this.poseidon = new Poseidon(hasherSpecPath, this.curve);
	}

	async load() {
		await this.poseidon.parseSpec();
		this.poseidon.loadState();
	}

	// Scalar is a Field element in field Fr
	writeScalar(scalar) {
		this.poseidon.update([scalar]);
	}

	// Point in on curve G1
	writePoint(point) {
		let x = this.G1.x(point);
		let y = this.G1.y(point);
		this.poseidon.update([x, y]);
	}

	// squeeze challenge
	squeezeChallenge() {
		return this.poseidon.squeeze();
	}
}
