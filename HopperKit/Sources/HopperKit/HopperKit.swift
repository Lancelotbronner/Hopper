public import CoreHopper

public extension HPSegment {
	@inlinable
	var mappedAddresses: Range<Address> {
		startAddress()..<endMappedDataAddress()
	}
}

public extension HPDisassembledFile {
	func type(withName name: String, orCreate create: () -> any HPTypeDesc & NSObjectProtocol) -> any HPTypeDesc & NSObjectProtocol {
		if let ty = type(withName: name) {
			return ty
		}
		let ty = create()
		ty.setName(name)
		return ty
	}
}
