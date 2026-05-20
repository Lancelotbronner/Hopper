//
//  HopperCpp.swift
//  HopperCpp
//
//  Created by Vincent Bénony on 26/04/2019.
//  Copyright © 2019 Cryptic Apps. All rights reserved.
//

import Foundation
import CoreHopper
import HopperKit

@objc(HopperCpp)
class HopperCpp : NSObject, HopperTool {
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
				HPM_TITLE: "Sample Tool Fct1",
				HPM_SELECTOR: "fct1:"
			],

			[
				HPM_TITLE: "Sample Tool Menu",
				HPM_SUBMENU: [
					[
						HPM_TITLE: "Fct 2",
						HPM_SELECTOR: "fct2:"
					],
					[
						HPM_TITLE: "Fct 3",
						HPM_SELECTOR: "fct3:"
					]
				]
			],
			[
				HPM_TITLE: "C++ RTTI",
				HPM_SUBMENU: [
					[
						HPM_TITLE: "Reload Type Descriptors",
						HPM_SELECTOR: "reloadTypeDescriptors:"
					]
				]
			]
		]
	}

	@objc func fct1(_ sender: AnyObject!) {
		if let doc = services.currentDocument() {
			doc.begin(toWait: "I'm waiting…")
			let msg = "Function1: address is \(String(format: "0x%llx", doc.currentAddress()))"
			doc.displayAlert(withMessageText: "Info",
							 defaultButton: "OK",
							 alternateButton: nil,
							 otherButton: nil,
							 informativeText: msg)
			doc.endWaiting()
		}
	}

	@objc func fct2(_ sender: AnyObject!) {
		if let doc = services.currentDocument() {
			doc.displayAlert(withMessageText: "Info",
							 defaultButton: "OK",
							 alternateButton: nil,
							 otherButton: nil,
							 informativeText: "Function 2 triggered")
		}
	}

	@objc func fct3(_ sender: AnyObject!) {
		if let doc = services.currentDocument() {
			doc.logStringMessage("Function 3 triggered")
		}
	}
}

extension HopperCpp {
	@objc func reloadTypeDescriptors(_ sender: AnyObject!) {
		guard
			let doc = services.currentDocument(),
			let file = doc.disassembledFile(),
			let data = file.segmentNamed(".data")
		else { return }

		doc.logInfoMessage("end \(data.endAddress()) vs mapped \(data.endMappedDataAddress())")
		return;

		doc.begin(toWait: "Reloading RTTI Type Descriptor")
		defer { doc.endWaiting() }

		let tag = file.buildTag("RTTI Type Descriptor")

		for addr in data.mappedAddresses {
			guard
				file.readInt8(atVirtualAddress: addr) == 0x2e,
				let mangled = file.readCString(at: addr),
				mangled.starts(with: ".?"),
				mangled.hasSuffix("@@")
			else { continue }

			file.setType(.Type_ASCII, atVirtualAddress: addr, forLength: mangled.count)

			let vftable = file.type(withName: "\(mangled)::vtable") {
				let ty = file.structureType()
				let vft = file.readAddress(atVirtualAddress: addr - 8)
				var vfi = 1
				while file.readUInt32(atVirtualAddress: vft) != 0 {
					let ftype = file.type(withName: "\(mangled)::vtable::vfunction\(vfi)") {
						//TODO: Create a function pointer here
						file.voidPtrType()
					}
					ty.addStructureField(ofType: ftype, named: "vfunction\(vfi)")
					vfi += 1
				}
				return ty
			}
			let ty = file.type(withName: "\(mangled)::RTTI_Type_Descriptor") {
				let ty = file.structureType()
				ty.addStructureField(ofType: vftable, named: "pVFTable", withComment: "Virtual Function Table")
				ty.addStructureField(ofType: file.voidPtrType(), named: "spare")
				ty.addStructureField(ofType: file.arrayType(of: file.charType(), withCount: UInt(mangled.count)), named: "name")
				return ty
			}

			file.defineStructure(ty, at: addr - 8)
			file.add(tag, at: addr - 8)

			let completion = Int(Double(addr) / Double(data.endMappedDataAddress()) * 100)
			doc.logInfoMessage("\(completion) \(mangled)")
		}

		/*
		 import hopper_api

		 doc = Document.getCurrentDocument()
		 rtty_tag = doc.buildTag("RTTI Type Descriptor")
		 seg = doc.getSegmentByName(".data")
		 adr = seg.getStartingAddress()
		 SOS = adr
		 EOS = adr + seg.getLength()
		 found = 0

		 print(f"Analyzing in {seg.getName()} from 0x{adr:X} to 0x{EOS:X}")
		 while adr < EOS:
			 # Bail out once we're no longer in the file
			 if doc.getFileOffsetFromAddress(adr) == -1:
				 break

			 # Look for the TypeDescriptor magic
			 if doc.readUInt32LE(adr) != 0x1170f5b4:
				 adr += 4
				 continue

			 # Identify the TypeDescriptor struct
			 # TODO: Mark as structure type {void*,void*,char[]}
			 base = adr
			 doc.addTagAtAddress(rtty_tag, base)
			 seg.setTypeAtAddress(base + 4, 4, Segment.TYPE_INT32)
			 adr += 8

			 # Parse the name
			 # TODO: should be part of the struct via char[]
			 start = adr
			 while doc.readByte(adr) != 0x00:
				 adr += 1
			 length = adr - start
			 seg.setTypeAtAddress(start, length, Segment.TYPE_ASCII)

			 # Demangle the type name and label the type descriptor
			 # TODO: Get Hopper's demangler working instead
			 name = doc.readBytes(start+1, length-1).decode()
			 name = seg.getDemangledNameAtAddress(start+1) or name
			 seg.setNameAtAddress(base, f"{name} RTTI Type Descriptor")
			 seg.setTypeAtAddress(base, 8, Segment.TYPE_STRUCTURE)

			 print(f"0x{base:x}  {name}")
			 found += 1

			 # Realign after name
			 # TODO: Figure out the proper alignments and set null bytes as alignment
			 min = adr
			 adr = base
			 while adr < min:
				 adr += 4

		 */
	}

	/*
	 import hopper_api

	 doc = Document.getCurrentDocument()
	 td_tag = doc.buildTag("RTTI Type Descriptor")
	 col_tag = doc.buildTag("RTTI Complete Object Locator")
	 chd_tag = doc.buildTag("RTTI Class Hierarchy Descriptor")
	 bca_tag = doc.buildTag("RTTI Base Class Array")
	 bcd_tag = doc.buildTag("RTTI Base Class Descriptor")
	 data = doc.getSegmentByName(".data")
	 rdata = doc.getSegmentByName(".rdata")
	 global found
	 found = 0

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
}
