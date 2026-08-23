#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	copyFileSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sourceRoot = join(repositoryRoot, "extensions", "sandbox");
const sourceManifest = JSON.parse(readFileSync(join(sourceRoot, "package.json"), "utf8"));
const nativePackages = {
	"darwin:arm64": {
		name: "pi-nono-darwin-arm64",
		os: "darwin",
		cpu: "arm64",
		format: "mach-o-arm64",
	},
	"linux:x64": {
		name: "pi-nono-linux-x64",
		os: "linux",
		cpu: "x64",
		format: "elf-x64",
	},
};

const [action, ...argv] = process.argv.slice(2);
const options = parseOptions(argv);
if (action === "main") buildMain(requiredAbsolute(options, "out"));
else if (action === "native") buildNative(options);
else fail("usage: build-packages.mjs main --out PATH | native --platform PLATFORM --arch ARCH --out PATH --nono PATH --nono-license PATH");

function buildMain(outputRoot) {
	const output = resetPackageDirectory(outputRoot, sourceManifest.name);
	for (const name of readdirSync(sourceRoot)) {
		if (name.endsWith(".ts") && !name.endsWith(".test.ts") && name !== "test-setup.ts") {
			copyFileSync(join(sourceRoot, name), join(output, name));
		}
	}
	copyFileSync(join(sourceRoot, "README.md"), join(output, "README.md"));
	copyFileSync(join(sourceRoot, "LICENSE"), join(output, "LICENSE"));
	const manifest = {
		...sourceManifest,
		private: false,
		scripts: {},
		files: ["*.ts", "README.md", "LICENSE"],
		optionalDependencies: Object.fromEntries(
			Object.values(nativePackages).map(({ name }) => [name, sourceManifest.version]),
		),
	};
	delete manifest.devDependencies;
	writeJson(join(output, "package.json"), manifest);
	process.stdout.write(`${output}\n`);
}

function buildNative(options) {
	const platform = required(options, "platform");
	const arch = required(options, "arch");
	const selected = nativePackages[`${platform}:${arch}`];
	if (!selected) fail(`unsupported native package target: ${platform}/${arch}`);
	const outputRoot = requiredAbsolute(options, "out");
	const nono = verifiedBinary(requiredAbsolute(options, "nono"), "nono", "0.61.1", selected.format);
	const nonoLicense = verifiedFile(requiredAbsolute(options, "nono-license"), "nono license");
	verifyPortableLinkage(nono.path, selected.os);

	const output = resetPackageDirectory(outputRoot, selected.name);
	mkdirSync(join(output, "bin"));
	mkdirSync(join(output, "LICENSES"));
	copyExecutable(nono.path, join(output, "bin", "nono"));
	copyFileSync(nonoLicense, join(output, "LICENSES", "NONO-APACHE-2.0.txt"));
	writeFileSync(join(output, "README.md"), nativeReadme(selected));
	writeJson(join(output, "package.json"), {
		name: selected.name,
		version: sourceManifest.version,
		description: `Fixed nono executable for ${sourceManifest.name} on ${platform}/${arch}`,
		license: "Apache-2.0",
		repository: sourceManifest.repository,
		os: [selected.os],
		cpu: [selected.cpu],
		...(selected.os === "linux" ? { libc: ["glibc"] } : {}),
		files: ["bin", "LICENSES", "README.md"],
		publishConfig: { access: "public", tag: "next" },
		scripts: {},
		piNono: {
			nono: { version: "0.61.1", sha256: nono.sha256, path: "bin/nono" },
		},
	});
	process.stdout.write(`${output}\n`);
}

function verifiedBinary(path, name, version, format) {
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o111) === 0) {
		fail(`${name} must be a regular executable file: ${path}`);
	}
	const realPath = realpathSync(path);
	const bytes = readFileSync(realPath);
	assertBinaryFormat(bytes, format, name);
	let output;
	try {
		output = execFileSync(realPath, ["--version"], { encoding: "utf8", timeout: 10_000 }).trim();
	} catch (error) {
		fail(`${name} --version failed: ${error instanceof Error ? error.message : error}`);
	}
	if (!new RegExp(`(?:^|[^0-9])${version.replaceAll(".", "\\.")}(?:[^0-9]|$)`).test(output)) {
		fail(`${name} must report version ${version}; got ${JSON.stringify(output)}`);
	}
	return { name, path: realPath, bytes, sha256: sha256(bytes) };
}

function verifyPortableLinkage(path, platform) {
	const tool = platform === "darwin" ? "/usr/bin/otool" : "/usr/bin/ldd";
	let output;
	try {
		output = execFileSync(tool, platform === "darwin" ? ["-L", path] : [path], {
			encoding: "utf8",
			timeout: 10_000,
		});
	} catch (error) {
		fail(`cannot inspect nono runtime linkage with ${tool}: ${error instanceof Error ? error.message : error}`);
	}
	if (/\/nix\/store|not found/i.test(output)) fail(`nono has non-portable runtime linkage:\n${output}`);
	const dependencyPaths = output.match(/\/(?:System|usr|lib|opt|nix)[^\s(]*/g) ?? [];
	const allowed = platform === "darwin" ? /^(?:\/usr\/lib|\/System\/Library)\// : /^(?:\/lib|\/usr\/lib)/;
	const unsupported = dependencyPaths.filter((dependency) => !allowed.test(dependency));
	if (unsupported.length > 0) fail(`nono has unsupported runtime dependencies: ${unsupported.join(", ")}`);
}

function assertBinaryFormat(bytes, format, name) {
	if (format === "mach-o-arm64") {
		if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0xfeedfacf || bytes.readUInt32LE(4) !== 0x0100000c) {
			fail(`${name} must be a 64-bit ARM Mach-O executable`);
		}
		return;
	}
	if (
		bytes.length < 20 ||
		bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46 ||
		bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== 62
	) {
		fail(`${name} must be a 64-bit x86 ELF executable`);
	}
}

function verifiedFile(path, label) {
	const metadata = lstatSync(path);
	if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) fail(`${label} must be a non-empty regular file`);
	return realpathSync(path);
}

function resetPackageDirectory(outputRoot, packageName) {
	if (resolve(outputRoot) === repositoryRoot) fail("output root cannot be the repository root");
	mkdirSync(outputRoot, { recursive: true });
	const output = join(outputRoot, packageName);
	rmSync(output, { recursive: true, force: true });
	mkdirSync(output);
	return output;
}

function copyExecutable(source, destination) {
	copyFileSync(source, destination);
	chmodSync(destination, 0o755);
}

function nativeReadme(selected) {
	return `# ${selected.name}\n\nFixed native executable package for \`${sourceManifest.name}@${sourceManifest.version}\`.\nIt is installed automatically as an optional dependency and has no lifecycle scripts.\n`;
}

function parseOptions(values) {
	const result = {};
	for (let index = 0; index < values.length; index += 2) {
		const key = values[index];
		const value = values[index + 1];
		if (!key?.startsWith("--") || value === undefined) fail(`invalid option near ${key ?? "end of arguments"}`);
		result[key.slice(2)] = value;
	}
	return result;
}

function required(options, name) {
	const value = options[name];
	if (!value) fail(`--${name} is required`);
	return value;
}

function requiredAbsolute(options, name) {
	const value = required(options, name);
	if (!isAbsolute(value)) fail(`--${name} must be absolute`);
	return resolve(value);
}

function writeJson(path, value) {
	writeFileSync(path, `${JSON.stringify(value, null, "\t")}\n`);
}

function sha256(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function fail(message) {
	throw new Error(message);
}
