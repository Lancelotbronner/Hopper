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

	func getOrCreateProcedure(at address: Address) -> (any HPProcedure & NSObjectProtocol)? {
		if let p = procedure(at: address) {
			return p
		}
		return makeProcedure(at: address)
	}

	func countOfNonNull32(at a: Address) -> UInt {
		var count: UInt = 0
		var a = a
		while readUInt32(atVirtualAddress: a) != 0 {
			count += 1
			a += 4
		}
		return count
	}
}
