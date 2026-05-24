//
//  HopperPlugin.swift
//  HopperPlugin
//
//  Created by Vincent Bénony on 26/04/2019.
//  Copyright © 2019 Cryptic Apps. All rights reserved.
//

import Foundation
import CoreHopper
import HopperKit

@objc(HopperCpp)
class HopperPlugin : NSObject, HopperTool {
	let services: HPHopperServices!

	static func sdkVersion() -> Int32 {
		HOPPER_CURRENT_SDK_VERSION
	}

	func pluginType() -> HopperPluginType {
		.Plugin_Tool
	}

	func pluginUUID() -> NSObjectProtocol & HPHopperUUID {
		services.uuid(with: "29ca3846-bc8c-4e31-85e0-95e08a673cdb")
	}

	func pluginName() -> String {
		"Hopper++"
	}

	func pluginDescription() -> String {
		"Analysis tool for C++"
	}

	func pluginAuthor() -> String {
		"Christophe Bronner"
	}

	func pluginCopyright() -> String {
		"© Christophe Bronner"
	}

	func commandLineIdentifiers() -> [String] {
		return ["Hopper++"]
	}

	func pluginVersion() -> String {
		return "0.0.0"
	}

	required init(hopperServices services: NSObjectProtocol & HPHopperServices) {
		self.services = services
		super.init()
	}

	func toolMenuDescription() -> [[String : Any]] {
		[
			[
				HPM_TITLE: "C++ for Windows PE",
				HPM_SUBMENU: [
					[
						HPM_TITLE: "Reload RTTI Type Descriptors",
						HPM_SELECTOR: "reloadTypeDescriptors:"
					],
					[
						HPM_TITLE: "Scan for Virtual Function Tables",
						HPM_SELECTOR: "scanForVirtualFunctionTables:",
					],
				]
			],
			[
				HPM_TITLE: "C++ for Itanium",
				HPM_SUBMENU: [
					[
						HPM_TITLE: "Create RTTI types",
						HPM_SELECTOR: "itanium_types:"
					],
				]
			]
		]
	}
}

extension HopperPlugin {
	static let type_info = ".?AVtype_info@@"

	@objc func itanium_types(_ sender: AnyObject!) {
		guard let ctx = Itanium(services: services) else { return }
		ctx.scan()
	}

	@objc func reloadTypeDescriptors(_ sender: AnyObject!) {
		guard let doc = services.currentDocument() else { return }
		doc.logInfoMessage("Analysis: Reloading RTTI Type Descriptors")
		doc.waitForBackgroundProcessToEnd()

		guard
			let file = doc.disassembledFile(),
			let data = file.segmentNamed(".data")
		else {
			doc.logErrorStringMessage("Failed to retrieve disassembled file or .data segment")
			return
		}

		DispatchQueue.global().async {
			let td_tag = file.buildTag("RTTI Type Descriptor")
			let vft_tag = file.buildTag("Virtual Function Table")
			let col_tag = file.buildTag("RTTI Complete Object Locator")
			let chd_tag = file.buildTag("RTTI Class Hierarchy Descriptor")
			let bca_tag = file.buildTag("RTTI Base Class Array")
			let bcd_tag = file.buildTag("RTTI Base Class Descriptor")
			var vft_ty: (any HPTypeDesc & NSObjectProtocol)!
			var found = 0

			let chd_ty = file.type(withName: "RTTI_Class_Hierarchy_Descriptor") {
				let ty = file.structureType()
				ty.addStructureField(ofType: file.uint32Type(), named: "signature")
				ty.addStructureField(ofType: file.uint32Type(), named: "attributes")
				ty.addStructureField(ofType: file.uint32Type(), named: "numBaseClasses")
				ty.addStructureField(ofType: file.voidPtrType(), named: "pBaseClassArray")
				return ty
			}

			let pmd_ty = file.type(withName: "RTTI_PMD") {
				let ty = file.structureType()
				ty.addStructureField(ofType: file.voidPtrType(), named: "mdisp")
				ty.addStructureField(ofType: file.voidPtrType(), named: "pdisp")
				ty.addStructureField(ofType: file.voidPtrType(), named: "vdisp")
				return ty
			}

			let bcd_ty = file.type(withName: "RTTI_Base_Class_Descriptor") {
				let ty = file.structureType()
				ty.addStructureField(ofType: file.voidPtrType(), named: "pTypeDescriptor")
				ty.addStructureField(ofType: file.uint32Type(), named: "numContainedBases")
				ty.addStructureField(ofType: pmd_ty, named: "where")
				ty.addStructureField(ofType: file.uint32Type(), named: "attributes")
				ty.addStructureField(ofType: file.voidPtrType(), named: "pClassDescriptor")
				return ty
			}

			let start = data.startAddress()
			let end = Double(data.endMappedDataAddress() - start)
			for addr in data.mappedAddresses {
				guard
					file.readInt8(atVirtualAddress: addr) == 0x2e,
					let mangled = file.readCString(at: addr),
					mangled.starts(with: ".?A"),
					mangled.hasSuffix("@@")
				else { continue }

				//NOTE: .?AV=classes, .?AU=structs

				//TODO: demangle the name
				file.setType(.Type_ASCII, atVirtualAddress: addr, forLength: mangled.count)

				// Only create the type_info::vftable infra once
				if vft_ty == nil {
					let vft_addr = file.readAddress(atVirtualAddress: addr - 8)

					vft_ty = file.vftable(
						withName: Self.type_info,
						at: vft_addr)

					let td_ty = file.rtti_typeDescriptor(
						withName: Self.type_info,
						withVirtualFunctionTable: vft_ty)

					file.defineStructure(vft_ty, at: vft_addr)
					file.add(vft_tag, at: vft_addr)
					file.setName("\(Self.type_info)::vftable", forVirtualAddress: vft_addr, reason: .NCReason_Automatic)

					let col_ty = file.rtti_completeObjectLocator(
						withName: Self.type_info,
						withTypeDescriptor: td_ty,
						withCallHierarchyDescriptor: chd_ty)

					let meta_addr = vft_addr - 4
					file.defineStructure(file.pointerType(on: col_ty), at: meta_addr)

					let col_addr = file.readAddress(atVirtualAddress: meta_addr)
					file.defineStructure(col_ty, at: col_addr)
					file.add(col_tag, at: col_addr)
					file.setName("\(Self.type_info)::RTTI_Complete_Object_Locator", forVirtualAddress: col_addr, reason: .NCReason_Automatic)

					let chd_addr = file.readAddress(atVirtualAddress: col_addr + 16)
					file.defineStructure(chd_ty, at: chd_addr)
					file.add(chd_tag, at: chd_addr)
					file.setName("\(Self.type_info)::RTTI_Class_Hierarchy_Descriptor", forVirtualAddress: chd_addr, reason: .NCReason_Automatic)

					let bca_addr = file.readAddress(atVirtualAddress: chd_addr + 12)
					let bca_count = file.readUInt32(atVirtualAddress: chd_addr + 8)
					file.defineStructure(file.arrayType(of: file.pointerType(on: bcd_ty), withCount: UInt(bca_count)), at: bca_addr)
					file.add(bca_tag, at: bca_addr)
					file.setName("\(Self.type_info)::RTTI_Base_Class_Array", forVirtualAddress: bca_addr, reason: .NCReason_Automatic)

					let bcd_addr = file.readAddress(atVirtualAddress: bca_addr)
					file.defineStructure(bcd_ty, at: bcd_addr)
					file.add(bcd_tag, at: bcd_addr)
					file.setName("\(Self.type_info)::RTTI_Base_Class_Descriptor", forVirtualAddress: bcd_addr, reason: .NCReason_Automatic)
				}

				let td_ty = file.rtti_typeDescriptor(
					withName: mangled,
					withVirtualFunctionTable: vft_ty)

				let td_addr = addr - 8
				file.defineStructure(td_ty, at: td_addr)
				file.add(td_tag, at: td_addr)
				file.setName("\(mangled)::RTTI_Type_Descriptor", forVirtualAddress: td_addr, reason: .NCReason_Automatic)

				found += 1
			}

			doc.logInfoMessage("Updated \(found) RTTI Type Descriptors")
		}
	}

	@objc func scanForVirtualFunctionTables(_ sender: AnyObject!) {
		guard var ctx = WindowsPE("Scan for Virtual Function Tables", services: services) else { return }
		let found = ctx.scanForVirtualFunctionTables()
		ctx.file.beginUndoRedoTransaction(withName: "Scan for Virtual Function Tables")
		ctx.doc.logInfoMessage("Scanned \(found) Virtual Function Tables")
		ctx.file.endUndoRedoTransaction()
	}

	func reloadCompleteObjectLocators(_ sender: AnyObject!) {
		guard let doc = services.currentDocument() else { return }
		doc.logInfoMessage("Analysis: Reloading RTTI Complete Object Locators")
		doc.waitForBackgroundProcessToEnd()

		guard
			let file = doc.disassembledFile(),
			let data = file.segmentNamed(".data"),
			let rdata = file.segmentNamed(".rdata")
		else {
			doc.logErrorStringMessage("Failed to retrieve disassembled file or .data segment")
			return
		}

		DispatchQueue.global().async {
			let td_tag = file.buildTag("RTTI Type Descriptor")
			let col_tag = file.buildTag("RTTI Complete Object Locator")
			let chd_tag = file.buildTag("RTTI Class Hierarchy Descriptor")
			let bca_tag = file.buildTag("RTTI Base Class Array")
			let bcd_tag = file.buildTag("RTTI Base Class Descriptor")
			var found = 0

			let start = data.startAddress()
			let end = Double(data.endMappedDataAddress() - start)
			for addr in data.mappedAddresses {


				found += 1
			}

			doc.logInfoMessage("Updated \(found) Complete Object Locators")
		}
	}
}

	/*
	 def references_from(seg, base, offset):
		 if seg.getTypeAtAddress(base) == Segment.TYPE_STRUCTURE:
			 addr = base
		 else:
			 addr = base+offset
		 return seg.getReferencesFromAddress(addr)

	 def rtti(adr, name):
		 base = adr - 12

		 # Identify the RTTI_Complete_Object_Locator struct
		 # TODO: Mark as structure type {u32,u32,u32,RTTI_Type_Descriptor*,RTTI_Class_Hierarchy_Descriptor*}
		 doc.addTagAtAddress(col_tag, base)
		 rdata.setNameAtAddress(base, f"{name} RTTI Complete Object Locator")
		 rdata.setTypeAtAddress(base, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+4, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+8, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+12, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+16, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+20, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base, 20, Segment.TYPE_STRUCTURE)
		 refs = rdata.getReferencesFromAddress(base) + rdata.getReferencesFromAddress(base+16)
		 if len(refs) == 0:
			 print("Complete Object Locator is empty")
			 print(f"{base:x}", rdata.getReferencesFromAddress(base))
			 print(f"{base+16:x}", rdata.getReferencesFromAddress(base+16))
			 doc.setCurrentAddress(base)
			 doc.moveCursorAtAddress(base)
			 return True
		 base = refs[0]

		 # Identify the RTTI_Class_Hierarchy_Descriptor struct
		 # TODO: Mark as structure type {u32,u32,u32,RTTI_Base_Class_Array*}
		 doc.addTagAtAddress(chd_tag, base)
		 rdata.setNameAtAddress(base, f"{name} RTTI Class Hierarchy Descriptor")
		 rdata.setTypeAtAddress(base, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+4, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+8, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+12, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base+16, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base, 16, Segment.TYPE_STRUCTURE)
		 if not rdata.readBytes(base+8, 4):
			 print("Class Hierarchy Descriptor outside segment")
			 print(f"{base+8:x}", doc.getSegmentAtAddress(base+8).getName())
			 doc.setCurrentAddress(base)
			 doc.moveCursorAtAddress(base)
			 return False

		 # Read how many base classes we have
		 n = rdata.readUInt32LE(base+8)
		 if n == 0:
			 return True

		 # Read the base classes
		 refs = references_from(rdata, base, 12)
		 if len(refs) == 0:
			 print("Class Hierarchy Descriptor is empty")
			 print(f"{base:x}", rdata.getReferencesFromAddress(base))
			 print(f"{base+12:x}", rdata.getReferencesFromAddress(base+12))
			 doc.setCurrentAddress(base)
			 doc.moveCursorAtAddress(base)
			 return True
		 base = refs[0]

		 # Identify the RTTI_Base_Class_Array struct
		 # TODO: Mark as structure type RTTI_Base_Class_Descriptor[]
		 doc.addTagAtAddress(bca_tag, base)
		 rdata.setNameAtAddress(base, f"{name} RTTI Base Class Array")
		 for i in range(n):
			 rdata.setTypeAtAddress(base+4*i, 4, Segment.TYPE_INT32)
		 rdata.setTypeAtAddress(base, 4 * n, Segment.TYPE_STRUCTURE)
		 refs = rdata.getReferencesFromAddress(base)
		 if len(refs) == 0:
			 print("Base Class Array is empty")
			 doc.setCurrentAddress(base)
			 doc.moveCursorAtAddress(base)
			 return False
		 base = min(refs, key=lambda x: abs(base-x))

		 # Identify the RTTI_Base_Class_Descriptor structs
		 # TODO: Mark as structure type RTTI_Base_Class_Descriptor
		 doc.addTagAtAddress(bcd_tag, base)
		 rdata.setTypeAtAddress(base, 28, Segment.TYPE_STRUCTURE)
		 rdata.setNameAtAddress(base, f"{name} RTTI Base Class Descriptor")
		 rdata.setTypeAtAddress(base+28, 8, Segment.TYPE_INT64)
		 return True

	 def analyse(refs):
		 global found
		 # Get the name of the symbol
		 name = doc.getNameAtAddress(addr)
		 name = name[:len(name)-21]

		 for ref in refs:
			 # If we've already tagged it, account for that
			 if rdata.getTypeAtAddress(ref) == Segment.TYPE_STRUCTURE:
				 ref += 12

			 if doc.getSegmentAtAddress(ref) != rdata:
				 continue

			 if not rtti(ref, name):
				 return False
			 found += 1
			 break
		 return True

	 addrs = data.getNamedAddresses()
	 print(f"Analyzing {len(addrs)} addresses in {data.getName()}")
	 for addr in addrs:
		 # Look for Type Descriptors
		 if not doc.hasTagAtAddress(td_tag, addr):
			 continue
		 # Only look for those with references
		 refs = data.getReferencesOfAddress(addr)

		 if len(refs) != 2:
			 continue
		 if not analyse(refs):
			 break

	 */
