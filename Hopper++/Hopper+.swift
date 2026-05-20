//
//  Hopper+.swift
//  HopperCpp
//
//  Created by Christophe Bronner on 2026-05-20.
//  Copyright © 2026 Cryptic Apps. All rights reserved.
//

import CoreHopper
import HopperKit

extension HPDisassembledFile {
	func vftable(withName name: String, at addr: Address) -> any HPTypeDesc & NSObjectProtocol {
		type(withName: "\(name)::vtable") {
			let ty = structureType()
			var vft = addr
			var vfi = 1
			while true {
				let addr = readAddress(atVirtualAddress: vft)
				guard addr != 0 else { break }
				//TODO: Create function pointers
				ty.addStructureField(ofType: voidPtrType(), named: "vfunction\(vfi)")
				if let procedure = getOrCreateProcedure(at: addr) {
					procedure.setCallingConvention(.thiscall)
					setName("\(name)::vfunction\(vfi)", forVirtualAddress: addr, reason: .NCReason_Automatic)
				}
				vfi += 1
				vft += 4
			}
			return ty
		}
	}

	func rtti_typeDescriptor(withName name: String, withVirtualFunctionTable vft_ty: any HPTypeDesc & NSObjectProtocol) -> any HPTypeDesc & NSObjectProtocol {
		//TODO: Collapse into a single type with variable size field char[]
		type(withName: "\(name)::RTTI_Type_Descriptor") {
			let ty = structureType()
			ty.addStructureField(ofType: pointerType(on: vft_ty), named: "pVFTable")
			ty.addStructureField(ofType: voidPtrType(), named: "spare")
			let name = arrayType(of: charType(), withCount: UInt(name.count))
			name.setSingleLineDisplay(true)
			//TODO: Display as Ascii
			ty.addStructureField(ofType: name, named: "name")
			return ty
		}
	}

	func rtti_completeObjectLocator(
		withName name: String,
		withTypeDescriptor td_ty: any HPTypeDesc & NSObjectProtocol,
		withCallHierarchyDescriptor chd_ty: any HPTypeDesc & NSObjectProtocol,
	) -> any HPTypeDesc & NSObjectProtocol {
		type(withName: "\(name)::RTTI_Complete_Object_Locator") {
			let ty = structureType()
			ty.addStructureField(ofType: uint32Type(), named: "signature")
			ty.addStructureField(ofType: uint32Type(), named: "offset")
			ty.addStructureField(ofType: uint32Type(), named: "cdOffset")
			ty.addStructureField(ofType: pointerType(on: td_ty), named: "pTypeDescriptor")
			ty.addStructureField(ofType: pointerType(on: chd_ty), named: "pClassDescriptor")
			ty.addStructureField(ofType: voidPtrType(), named: "pSelf")
			return ty
		}
	}
}
