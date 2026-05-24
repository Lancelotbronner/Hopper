//
//  Itanium.swift
//  HopperCpp
//
//  Created by Christophe Bronner on 2026-05-21.
//  Copyright © 2026 Cryptic Apps. All rights reserved.
//

import CoreHopper

struct Itanium {
	let services: any HPHopperServices
	let doc: any HPDocument & NSObjectProtocol
	let file: any HPDisassembledFile & NSObjectProtocol
	let cti_tag: any HPTag & NSObjectProtocol
	let vft_tag: any HPTag & NSObjectProtocol
	let cti_ty: any HPTypeDesc & NSObjectProtocol
	let cti_si_ty: any HPTypeDesc & NSObjectProtocol
	let cti_vmi_ty: any HPTypeDesc & NSObjectProtocol
	let cti_vmi_flags_ty: any HPTypeDesc & NSObjectProtocol
	let cti_vmi_entry_ty: any HPTypeDesc & NSObjectProtocol
	let cti_vmi_entry_flags_ty: any HPTypeDesc & NSObjectProtocol
	let text: any HPSegment & NSObjectProtocol
	let data: any HPSegment & NSObjectProtocol

	private var td_count = 0
	private var vft_count = 0
	private var col_count = 0
	private var chd_count = 0
	private var bca_count = 0
	private var bcd_count = 0

	private var _td: Set<Address> = []
	private var _vft: Set<Address> = []
	private var _col: Set<Address> = []
	private var _chd: Set<Address> = []
	private var _bca: Set<Address> = []
	private var _bcd: Set<Address> = []

	init(
		services: any HPHopperServices,
		doc: any HPDocument & NSObjectProtocol,
		file: any HPDisassembledFile & NSObjectProtocol,
		text: any HPSegment & NSObjectProtocol,
		data: any HPSegment & NSObjectProtocol,
	) {
		self.services = services
		self.doc = doc
		self.file = file
		self.text = text
		self.data = data
		cti_tag = file.buildTag("RTTI Class Type Info")
		vft_tag = file.buildTag("Virtual Function Table")
		cti_ty = file.type(withName: "__class_type_info") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "vptr", withComment: "vtable of __class_type_info  ")
			ty.addStructureField(ofType: file.voidPtrType(), named: "__name", withComment: "pointer to _ZTS<class> ")
			return ty
		}
		cti_si_ty = file.type(withName: "__si_class_type_info") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "vptr", withComment: "vtable of __class_type_info  ")
			ty.addStructureField(ofType: file.voidPtrType(), named: "__name", withComment: "pointer to _ZTS<class> ")
			ty.addStructureField(ofType: file.voidPtrType(), named: "__base_type", withComment: "pointer to _ZTI<parent> (__class_type_info)")
			return ty
		}
		let flags_ty = file.type(withName: "__vmi_class_type_info::flags") {
			let ty = file.enumType(withBaseType: file.uint32Type())
			ty.addEnumField(withName: "__non_diamond_repeat_mask", andValue: 0x1)
			ty.addEnumField(withName: "__diamond_shaped_mask", andValue: 0x2)
			return ty
		}
		self.cti_vmi_flags_ty = flags_ty
		cti_vmi_ty = file.type(withName: "__vmi_class_type_info") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "vptr", withComment: "vtable of __class_type_info  ")
			ty.addStructureField(ofType: file.voidPtrType(), named: "__name", withComment: "pointer to _ZTS<class> ")
			ty.addStructureField(ofType: file.uint32Type(), named: "__flags")
			ty.addStructureField(ofType: file.uint32Type(), named: "__base_count")
			return ty
		}
		let entry_flags_ty = file.type(withName: "__vmi_class_type_info::entry::flags") {
			let ty = file.enumType(withBaseType: file.uint32Type())
			ty.addEnumField(withName: "__virtual_mask", andValue: 0x1)
			ty.addEnumField(withName: "__public_mask", andValue: 0x2)
			return ty
		}
		self.cti_vmi_entry_flags_ty = flags_ty
		cti_vmi_entry_ty = file.type(withName: "__vmi_class_type_info::entry") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "__base_type")
			ty.addStructureField(ofType: entry_flags_ty, named: "__offset_flags")
			return ty
		}
	}

	init?(services: (any HPHopperServices)?) {
		guard
			let services,
			let doc = services.currentDocument()
		else { return nil }
		doc.waitForBackgroundProcessToEnd()

		guard
			let file = doc.disassembledFile(),
			let text = file.segmentNamed("__TEXT"),
			let data = file.segmentNamed("__DATA")
		else { return nil }

		self.init(
			services: services,
			doc: doc,
			file: file,
			text: text,
			data: data)
	}
}

extension Itanium {
	func label(_ addr: Address, as name: String, for task: String) {
		let existing = file.findVirtualAddressNamed(name)
		if existing > 0 {
			doc.logErrorStringMessage("Collision for \(task) between \(existing) and \(addr)\n\t\(name)")
		}
		file.setName(name, forVirtualAddress: addr, reason: .NCReason_Automatic)
	}

	func scan() {
		scanConstSection()
		scanDataSection()
	}

	func scanConstSection() {
		guard let section = file.sectionNamed("__const") else {
			doc.logErrorStringMessage("Could not locate '__const' section")
			return
		}

		doc.logInfoMessage("Analysis: C++ RTTI Strings")

		let ptrwidth = Address(file.integerWidthInBits() / 8)
		var a = section.startAddress()
		let endOfData = section.endAddress()
		while a < endOfData {
			defer { a += ptrwidth }
			guard
				let lbl = file.name(forVirtualAddress: a),
					lbl.starts(with: "_ZTS")
			else { continue }
			var r = a
			while file.readInt8(atVirtualAddress: r) != 0 {
				r += 1
			}
			let len = Int(r - a)
			file.setType(.Type_ASCII, atVirtualAddress: a, forLength: len)
		}
	}

	func scanDataSection() {
		guard let data = file.sectionNamed("__data") else {
			doc.logErrorStringMessage("Could not locate '__data' section")
			return
		}

		doc.logInfoMessage("Analysis: C++ RTTI Class Type Info")

		let cti_addr = file.findVirtualAddressNamed("__ZTVN10__cxxabiv117__class_type_infoE")
		let cti_si_addr = file.findVirtualAddressNamed("__ZTVN10__cxxabiv120__si_class_type_infoE")
		let cti_vmi_addr = file.findVirtualAddressNamed("__ZTVN10__cxxabiv121__vmi_class_type_infoE")
		guard
			cti_addr != 0,
			cti_si_addr != 0
		else {
			doc.logErrorStringMessage("Failed to locate C++ ABI labels")
			return
		}

		let ptrwidth = Address(file.integerWidthInBits() / 8)
		var a = data.startAddress()
		let endOfData = data.endAddress()
		while a < endOfData {
			defer { a += ptrwidth }
			guard let lbl = file.name(forVirtualAddress: a) else { continue }

			if lbl.starts(with: "_ZTI") {
				let type_info_addr = file.readAddress(atVirtualAddress: a)
				switch type_info_addr {
				case cti_addr:
					file.defineStructure(cti_ty, at: a)
					a += ptrwidth * 2
				case cti_si_addr:
					file.defineStructure(cti_si_ty, at: a)
					a += ptrwidth * 3
				case cti_vmi_addr:
					file.defineStructure(cti_vmi_ty, at: a)
					let count = file.readInt32(atVirtualAddress: a + 20)
					a += ptrwidth * 3
					for i in 0..<count {
						file.defineStructure(cti_vmi_entry_ty, at: a)
						a += ptrwidth * 2
					}
				default: break
				}
			}

			if lbl.starts(with: "_ZTV") {

			}
		}
	}

	private static let ZTV_PREFIX = "typeinfo for "

	private func scanZTV(_ lbl: String, at a: Address, in section: any HPSection) {
		guard
			let comment = file.inlineComment(atVirtualAddress: a),
			comment.starts(with: Self.ZTV_PREFIX)
		else {
			doc.logStringMessage("Cannot retrieve name for \(lbl)")
			return
		}
		let name = String(comment.dropFirst(Self.ZTV_PREFIX.count))
		let ty = file.type(withName: "\(lbl)") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "vtbl")
			return ty
		}
	}
}
