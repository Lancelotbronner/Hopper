//
//  WindowsPE.swift
//  HopperCpp
//
//  Created by Christophe Bronner on 2026-05-20.
//  Copyright © 2026 Cryptic Apps. All rights reserved.
//

import CoreHopper

struct WindowsPE {
	let services: any HPHopperServices
	let doc: any HPDocument & NSObjectProtocol
	let file: any HPDisassembledFile & NSObjectProtocol
	let td_tag: any HPTag & NSObjectProtocol
	let vft_tag: any HPTag & NSObjectProtocol
	let col_tag: any HPTag & NSObjectProtocol
	let chd_tag: any HPTag & NSObjectProtocol
	let bca_tag: any HPTag & NSObjectProtocol
	let bcd_tag: any HPTag & NSObjectProtocol
	let col_ty: any HPTypeDesc & NSObjectProtocol
	let col_ptr_ty: any HPTypeDesc & NSObjectProtocol
	let chd_ty: any HPTypeDesc & NSObjectProtocol
	let pmd_ty: any HPTypeDesc & NSObjectProtocol
	let bcd_ty: any HPTypeDesc & NSObjectProtocol
	let text: any HPSegment & NSObjectProtocol
	let data: any HPSegment & NSObjectProtocol
	let rdata: any HPSegment & NSObjectProtocol

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
		rdata: any HPSegment & NSObjectProtocol,
	) {
		self.services = services
		self.doc = doc
		self.file = file
		self.text = text
		self.data = data
		self.rdata = rdata
		td_tag = file.buildTag("RTTI Type Descriptor")
		vft_tag = file.buildTag("Virtual Function Table")
		col_tag = file.buildTag("RTTI Complete Object Locator")
		chd_tag = file.buildTag("RTTI Class Hierarchy Descriptor")
		bca_tag = file.buildTag("RTTI Base Class Array")
		bcd_tag = file.buildTag("RTTI Base Class Descriptor")
		col_ty = file.type(withName: "RTTI_Complete_Object_Locator") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.uint32Type(), named: "signature")
			ty.addStructureField(ofType: file.uint32Type(), named: "offset")
			ty.addStructureField(ofType: file.uint32Type(), named: "cdOffset")
			ty.addStructureField(ofType: file.voidPtrType(), named: "pTypeDescriptor")
			ty.addStructureField(ofType: file.voidPtrType(), named: "pClassDescriptor")
			ty.addStructureField(ofType: file.voidPtrType(), named: "pSelf")
			return ty
		}
		col_ptr_ty = file.pointerType(on: col_ty)
		chd_ty = file.type(withName: "RTTI_Class_Hierarchy_Descriptor") {
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
		self.pmd_ty = pmd_ty
		bcd_ty = file.type(withName: "RTTI_Base_Class_Descriptor") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "pTypeDescriptor")
			ty.addStructureField(ofType: file.uint32Type(), named: "numContainedBases")
			ty.addStructureField(ofType: pmd_ty, named: "where")
			ty.addStructureField(ofType: file.uint32Type(), named: "attributes")
			ty.addStructureField(ofType: file.voidPtrType(), named: "pClassDescriptor")
			return ty
		}
	}

	init?(_ analysis: String, services: (any HPHopperServices)?) {
		guard
			let services,
			let doc = services.currentDocument()
		else { return nil }
		doc.logInfoMessage("Analysis: \(analysis)")
		doc.waitForBackgroundProcessToEnd()

		guard
			let file = doc.disassembledFile(),
			let text = file.segmentNamed(".text"),
			let data = file.segmentNamed(".data"),
			let rdata = file.segmentNamed(".rdata")
		else { return nil }

		self.init(
			services: services,
			doc: doc,
			file: file,
			text: text,
			data: data,
			rdata: rdata)
	}
}

extension WindowsPE {
	func label(_ addr: Address, as name: String, for task: String) {
		let existing = file.findVirtualAddressNamed(name)
		if existing > 0 {
			doc.logErrorStringMessage("Collision for \(task) between \(existing) and \(addr)\n\t\(name)")
		}
		file.setName(name, forVirtualAddress: addr, reason: .NCReason_Automatic)
	}

	/// Check if Dword(vtbl-4) points to typeinfo record and extract the type name from it.
	func isValidCOL(at col: Address) -> Bool {
		let td = file.readAddress(atVirtualAddress: col+12)
		if td == 0 { return false }
		let x = file.readInt32(atVirtualAddress: td+8)
		return x & 0xFFFFFF == 0x413F2E // .?A
	}

	func nameOfVtbl(at vtbl: Address) -> String {
		nameOfCol(at: vtbl - 4)

		/*
		 //get class name for this vtable instance
		 static GetVtableClass(x)
		 {
		   auto offset, n, i, s, a, p;
		   offset = Dword(x+4);
		   x = Dword(x+16); //Class Hierarchy Descriptor

		   a=Dword(x+12); //pBaseClassArray
		   n=Dword(x+8);  //numBaseClasses
		   i = 0;
		   s = "";
		   while(i<n)
		   {
			 p = Dword(a);
			 //Message(indent_str+"    BaseClass[%02d]:  %08.8Xh\n", i, p);
			 if (Dword(p+8)==offset)
			 {
			   //found it
			   s = GetAsciizStr(Dword(p)+8);
			   return s;
			 }
			 i=i+1;
			 a=a+4;
		   }
		   //didn't find matching one, let's get the first vbase
		   i=0;
		   a=Dword(x+12);
		   while(i<n)
		   {
			 p = Dword(a);
			 if (Dword(p+12)!=-1)
			 {
			   s = GetAsciizStr(Dword(p)+8);
			   return s;
			 }
			 i=i+1;
			 a=a+4;
		   }
		   return s;
		 }
		 */
	}

	func nameOfTd(at td_addr: Address) -> String {
		file.readCString(at: td_addr + 8) ?? ""
	}

	func sizeOfVtbl(at vtbl: Address) -> UInt {
		file.countOfNonNull32(at: vtbl + 8)
	}

	func tdOfCol(at col: Address) -> Address {
		file.readAddress(atVirtualAddress: col+12)
	}

	func typeOfVtbl(withName name: String, at vft: Address) -> any HPTypeDesc & NSObjectProtocol {
		file.type(withName: "\(name)::vtable") {
			let ty = file.structureType()
			var vft = vft
			var vfi = 1
			while true {
				let addr = file.readAddress(atVirtualAddress: vft)
				guard addr != 0 else { break }
				//TODO: Create function pointers
				ty.addStructureField(ofType: file.voidPtrType(), named: "vfunction\(vfi)")
				markVfn(withName: name, for: vfi, at: addr)
				vfi += 1
				vft += 4
			}
			return ty
		}
	}

	func markVfn(withName name: String, for i: Int, at vfn_addr: Address) {
		guard let procedure = file.getOrCreateProcedure(at: vfn_addr) else { return }
		procedure.setCallingConvention(.thiscall)
		label(vfn_addr, as: "\(name)::vfunction\(i)", for: "Virtual Function")
	}

	func nameOfCol(at col: Address) -> String {
		let td_addr = file.readAddress(atVirtualAddress: col+12)
		return nameOfTd(at: td_addr)
	}

	func markTd(withName name: String, at td_addr: Address) {
		//TODO: Collapse into a single type with variable size field char[]
		let td_ty = file.type(withName: "RTTI_Type_Descriptor (char[\(name.count)])") {
			let ty = file.structureType()
			ty.addStructureField(ofType: file.voidPtrType(), named: "pVFTable")
			ty.addStructureField(ofType: file.voidPtrType(), named: "spare")
			let name = file.arrayType(of: file.charType(), withCount: UInt(name.count))
			name.setSingleLineDisplay(true)
			//TODO: Display as Ascii
			ty.addStructureField(ofType: name, named: "name")
			return ty
		}
		file.defineStructure(td_ty, at: td_addr)
		file.add(td_tag, at: td_addr)
		label(td_addr, as: "\(name)::RTTI_Type_Descriptor", for: "Type Descriptor")
	}

	func markCol(withName name: String, at col_addr: Address) {
		file.defineStructure(col_ty, at: col_addr)
		file.add(col_tag, at: col_addr)
		label(col_addr, as: "\(name)::RTTI_Complete_Object_Locator", for: "Complete Object Locator")
	}

	mutating func markColAndFriends(withName name: String? = nil, at col_addr: Address) {
		guard !_col.contains(col_addr) else { return }
		_col.insert(col_addr)

		let name = name ?? nameOfCol(at: col_addr)
		markCol(withName: name, at: col_addr)

		let chd_addr = chdOfCol(at: col_addr)
		markChdAndFriends(withName: name, at: chd_addr)
	}

	func markVtbl(withName name: String, at vft_addr: Address) {
		let vft_ty = typeOfVtbl(withName: name, at: vft_addr)
		file.defineStructure(vft_ty, at: vft_addr)
		file.add(vft_tag, at: vft_addr)
		label(vft_addr, as: "\(name)::vftable", for: "Virtual Function Table")
	}

	func colOfVtbl(at vft_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: vft_addr - 4)
	}

	func chdOfCol(at col_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: col_addr + 16)
	}

	mutating func markVtblAndFriends(at vft_addr: Address) {
		guard !_vft.contains(vft_addr) else { return }
		_vft.insert(vft_addr)

		let meta_addr = vft_addr - 4
		file.defineStructure(col_ptr_ty, at: meta_addr)

		let col_addr = colOfVtbl(at: vft_addr)
		let td_addr = tdOfCol(at: col_addr)
		let name = String(nameOfCol(at: col_addr)[...])
		markColAndFriends(withName: name, at: col_addr)
		markTd(withName: name, at: td_addr)
		markVtbl(withName: name, at: vft_addr)
	}

	func markChd(withName name: String, at chd_addr: Address) {
		file.defineStructure(chd_ty, at: chd_addr)
		file.add(chd_tag, at: chd_addr)
		label(chd_addr, as: "\(name)::RTTI_Class_Hierarchy_Descriptor", for: "Class Hierarchy Descriptor")
	}

	func sizeOfBca(at bca_addr: Address) -> UInt {
		file.countOfNonNull32(at: bca_addr)
	}

	func sizeOfBcaInChd(at chd_addr: Address) -> UInt {
		UInt(file.readUInt32(atVirtualAddress: chd_addr + 8))
	}

	func bcaOfChd(at chd_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: chd_addr + 12)
	}

	func tdOfBcd(at bcd_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: bcd_addr)
	}

	mutating func markChdAndFriends(withName name: String, at chd_addr: Address) {
		guard !_chd.contains(chd_addr) else { return }
		_chd.insert(chd_addr)

		let bca_addr = bcaOfChd(at: chd_addr)
		let bca_count = sizeOfBcaInChd(at: chd_addr)
		markChd(withName: name, at: chd_addr)
		markBca(withName: name, count: UInt(bca_count), at: bca_addr)

		for i in 0..<Address(bca_count) {
			let bcd_addr = bcd(at: i, ofBca: bca_addr)
			markBcdAndFriends(at: bcd_addr)
		}
	}

	func markBca(withName name: String, count: UInt, at bca_addr: Address) {
		let bca_count = file.countOfNonNull32(at: bca_addr)
		if count != bca_count {
			doc.logErrorStringMessage("Failed to mark Base Class Array at \(bca_addr): expected \(count) entries but found \(bca_count)")
			//TODO: Ask user whether to proceed?
			return
		}
		file.defineStructure(file.arrayType(of: file.pointerType(on: bcd_ty), withCount: UInt(bca_count)), at: bca_addr)
		file.add(bca_tag, at: bca_addr)
		label(bca_addr, as: "\(name)::RTTI_Base_Class_Array", for: "Base Class Array")
	}

	func bcd(at i: Address, ofBca bca_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: bca_addr + i * 4)
	}

	func markBcd(withName name: String, at bcd_addr: Address) {
		file.defineStructure(bcd_ty, at: bcd_addr)
		file.add(bcd_tag, at: bcd_addr)
		label(bcd_addr, as: "\(name)::RTTI_Base_Class_Descriptor", for: "Base Class Descriptor")
	}

	func chdOfBcd(at bcd_addr: Address) -> Address {
		file.readAddress(atVirtualAddress: bcd_addr + 24)
	}

	mutating func markBcdAndFriends(at bcd_addr: Address) {
		guard !_bcd.contains(bcd_addr) else { return }
		_bcd.insert(bcd_addr)

		let td_addr = tdOfBcd(at: bcd_addr)
		let chd_addr = chdOfBcd(at: bcd_addr)
		let name = nameOfTd(at: td_addr)
		markBcd(withName: name, at: bcd_addr)
		markTd(withName: name, at: td_addr)
		markChdAndFriends(withName: name, at: chd_addr)
	}

	mutating func scanVtbl(at a: Address) -> Bool {
		/*
		  //check if it looks like a vtable
		  y = GetVtableSize(a);
		  if (y==0)
			return a+4;
		  s = form("%08.8Xh: possible vtable (%d methods)\n", a, y);
		  Message(s);
		  fprintf(f,s);

		  //check if it's named as a vtable
		  name = Name(a);
		  if (substr(name,0,4)!="??_7") name=0;
		 */

		// Otherwise try to get it from RTTI
		let x = file.readAddress(atVirtualAddress: a - 4)
		if isValidCOL(at: x) {
			markVtblAndFriends(at: a)
			return true
		}

		return false
	}

	mutating func scanForVirtualFunctionTables() -> Int {
		var found = 0
		for a in rdata.mappedAddresses where a % 4 == 0 {
			let x = file.readAddress(atVirtualAddress: a)
			guard text.containsVirtualAddress(x) else { continue }
			found += scanVtbl(at: a) ? 1 : 0
		}
		return found
	}
}
