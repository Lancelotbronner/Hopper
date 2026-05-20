// swift-tools-version: 6.3

import PackageDescription

let package = Package(
	name: "HopperKit",
	products: [
		.library(name: "CoreHopper", type: .dynamic, targets: [
			"HopperKit"
		]),
	],
	targets: [
		.target(name: "CoreHopper"),
		.target(name: "HopperKit", dependencies: ["CoreHopper"]),
	],
	swiftLanguageModes: [.v6]
)
