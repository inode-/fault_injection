//
//@author inode
//@category Emulation
//@keybinding 
//@menupath 
//@toolbar


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.datastruct.ByteArray;
import ghidra.util.exception.CancelledException;

public class xtensa_emulator extends GhidraScript {
	
	
	long init_addr = 0x400d70e4;
	
	long initial_instruction = 0x400d70e4;
	FileWriter outfile;
	
	
	public byte[] longToBytes_24bits(long l) {
	    
		byte[] result = new byte[3];
	    	    
	    for (int i = 2; i >= 0; i--) {
	        result[i] = (byte)(l & 0xFF);
	        l >>= 8;
	    }
	    return result;
	}
	
	
	void patch_code(long newcode[]) throws CancelledException, MemoryAccessException
	{
		Address current_instruction = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(init_addr);

		for(int i = 0; i < newcode.length; i++) 
		{
			clearListing(current_instruction);
	
			this.setBytes(current_instruction, longToBytes_24bits(newcode[i]));			
			
		
			current_instruction = current_instruction.add(3);
		
		}
		
		disassemble(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(init_addr));
		
		return;
	
	}
	
	int emulate_code(EmulatorHelper emuHelper, int array_size) throws IOException, MemoryAccessException, AddressOutOfBoundsException
	{
		emuHelper.writeRegister("a0", 0x40404040);
		emuHelper.writeRegister("a1", 0x41414141);
		emuHelper.writeRegister("a2", 0x42424242);
		emuHelper.writeRegister("a3", 0x43434343);
		emuHelper.writeRegister("a4", 0x44444444);
		emuHelper.writeRegister("a5", 0x45454545);
		emuHelper.writeRegister("a6", 0x46464646);
		emuHelper.writeRegister("a7", 0x47474747);
		emuHelper.writeRegister("a8", 0x48484848);
		emuHelper.writeRegister("a9", 0x49494949);
		emuHelper.writeRegister("a10", 0x50505050);
		emuHelper.writeRegister("a11", 0x51515151);
		emuHelper.writeRegister("a12", 0x52525252);
		emuHelper.writeRegister("a13", 0x93939393);
		emuHelper.writeRegister("a14", 0x54545454);
		emuHelper.writeRegister("a15", 0x55555555);
		
		emuHelper.writeRegister("a6", 0x0);
		
		emuHelper.writeRegister(emuHelper.getPCRegister(), initial_instruction);
		
		int j = 0;

		print("emulate\n");
		
		for(int i = 0; i<=array_size; i++)
		{
			Address executionAddress = emuHelper.getExecutionAddress();
			
			outfile.write(executionAddress.toString() + ' ' + getInstructionAt(executionAddress) + "\n");
			
			try {
			
				/*if (getInstructionAt(executionAddress) == null) {
					outfile.write(HexFormat.of().formatHex(getBytes(executionAddress, 3)));
					println("AAAAAAAAAAAAAABBBBBBBBBBBB");
					println(HexFormat.of().formatHex(getBytes(executionAddress, 3)));
					
					return -1;
				}*/
				
				boolean success = emuHelper.step(monitor);
		        
		        j++;
		        if( success == false) {
		        	String lastError = emuHelper.getLastError();
		        	outfile.write(lastError  + " - " +  getInstructionAt(executionAddress) + "\n");
		        	outfile.write(HexFormat.of().formatHex(getBytes(executionAddress, 3)));
		        	
		        	
		        	
		        	
		        	
		        	return -1;
		        }
			} catch (Exception e) {
				println(e.toString());
				return -1;
				
			}
			
		}
		
		//StoreProhibited - PC: 0x400d7125 - A5 : 0x0000003f(0x0000007f)  - A6 : 0x00000000(0x0000007f)  - 


		if(emuHelper.readRegister("a0").longValue() != 0x40404040 )
			outfile.write("A0 : 0x" + String.format("%08x", emuHelper.readRegister("a0").longValue()) + " ");
		if(emuHelper.readRegister("a1").longValue() != 0x41414141 )
			outfile.write("A1 : 0x" + String.format("%08x",emuHelper.readRegister("a1").longValue()) + " ");
		if(emuHelper.readRegister("a2").longValue() != 0x42424242 )
			outfile.write("A2 : 0x" + String.format("%08x",emuHelper.readRegister("a2").longValue()) + " ");
		if(emuHelper.readRegister("a3").longValue() != 0x43434343 )
			outfile.write("A3 : 0x" + String.format("%08x",emuHelper.readRegister("a3").longValue()) + " ");
		if(emuHelper.readRegister("a4").longValue() != 0x44444444 )
			outfile.write("A4 : 0x" + String.format("%08x",emuHelper.readRegister("a4").longValue()) + " ");
		if(emuHelper.readRegister("a5").longValue() != 0x45454545 )
			outfile.write("A5 : 0x" + String.format("%08x",emuHelper.readRegister("a5").longValue()) + " ");
		if(emuHelper.readRegister("a6").longValue() != 0x7f )
			outfile.write("A6 : 0x" + String.format("%08x",emuHelper.readRegister("a6").longValue()) + " ");
		if(emuHelper.readRegister("a7").longValue() != 0x47474747 )
			outfile.write("A7 : 0x" + String.format("%08x",emuHelper.readRegister("a7").longValue()) + " ");
		if(emuHelper.readRegister("a8").longValue() != 0x48484848 )
			outfile.write("A8 : 0x" + String.format("%08x",emuHelper.readRegister("a8").longValue()) + " ");
		if(emuHelper.readRegister("a9").longValue() != 0x49494949 )
			outfile.write("A9 : 0x" + String.format("%08x",emuHelper.readRegister("a9").longValue()) + " ");
		if(emuHelper.readRegister("a10").longValue() != 0x50505050 )
			outfile.write("A10 : 0x" + String.format("%08x",emuHelper.readRegister("a10").longValue()) + " ");
		if(emuHelper.readRegister("a11").longValue() != 0x51515151 )
			outfile.write("A11 : 0x" + String.format("%08x",emuHelper.readRegister("a11").longValue()) + " ");
		if(emuHelper.readRegister("a12").longValue() != 0x52525252 )
			outfile.write("A12 : 0x" + String.format("%08x",emuHelper.readRegister("a12").longValue()) + " ");
		if(emuHelper.readRegister("a13").longValue() != 0x93939393L )
			outfile.write("A13 : 0x" + String.format("%08x",emuHelper.readRegister("a13").longValue()) + " ");
		if(emuHelper.readRegister("a14").longValue() != 0x54545454 )
			outfile.write("A14 : 0x" + String.format("%08x",emuHelper.readRegister("a14").longValue()) + " ");
		if(emuHelper.readRegister("a15").longValue() != 0x55555555 )
			outfile.write("A15 : 0x" + String.format("%08x",emuHelper.readRegister("a15").longValue()) + " ");
		outfile.write(HexFormat.of().formatHex(getBytes(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(init_addr), 3*7)));
		outfile.write("\n");
		
		return 0;

	
	}
	
	int recursive_execute(ArrayList<ArrayList<Long> > aList, int deep, long newcode[]) throws CancelledException, MemoryAccessException, IOException
	{
		long[] newcode_next;
		
		if( deep >= aList.size())
		{
			
			patch_code(newcode);
			
			outfile.write("#########################################################################\n");
			
			EmulatorHelper emuHelper = new EmulatorHelper(currentProgram);
			
			if ( emulate_code(emuHelper, newcode.length) < 0 )
				return -1;

			return 0;
			
		}

		
		newcode_next = new long[newcode.length + 1];
		
		for (int i = 0; i < newcode.length ; i++)
			newcode_next[i] = newcode[i];
				
		for(int i = 0; i < aList.get(deep).size() ; i++)
		{
			newcode_next[newcode_next.length - 1] = aList.get(deep).get(i); 
					
			if (recursive_execute(aList, deep + 1, newcode_next) < 0)
				return -1;
		}

		return 0;
	}
	

	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		
		
		ArrayList<ArrayList<Long> > aList =  new ArrayList<ArrayList<Long>>();
		ArrayList<Long> a1 = new ArrayList<Long>(); 
		
		a1 = new ArrayList<Long>(Arrays.asList(0x62c601l, 0x60c601L, 0x42c601L, 0x22c601L, 0x62c401L, 0x62c201L, 0x628601L, 0x624601L, 0x62c600L, 0x2c601L, 0x62c001L, 0x620601L, 0x624600L, 0x620600L));
		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c602L, 0x60c602L, 0x42c602L, 0x22c602L, 0x62c402L, 0x62c202L, 0x628602L, 0x624602L, 0x62c600L, 0x2c602L, 0x62c002L, 0x620602L, 0x624600L));
		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c604L, 0x60c604L, 0x42c604L, 0x22c604L, 0x62c404L, 0x62c204L, 0x628604L, 0x624604L, 0x62c600L, 0x2c604L, 0x62c004L, 0x620604L));
		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c608L, 0x60c608L, 0x42c608L, 0x22c608L, 0x62c408L, 0x62c208L, 0x628608L, 0x624608L, 0x62c600L, 0x2c608L, 0x62c008L, 0x620608L));


		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c610L, 0x60c610L, 0x42c610L, 0x22c610L, 0x62c410L, 0x62c210L, 0x628610L, 0x624610L, 0x62c600L, 0x2c610L, 0x62c010L, 0x620610L));
		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c620L, 0x60c620L, 0x42c620L, 0x22c620L, 0x62c420L, 0x62c220L, 0x628620L, 0x624620L, 0x62c600L, 0x2c620L, 0x62c020L, 0x620620L));
		aList.add(a1);
		a1 = new ArrayList<Long>(Arrays.asList(0x62c640L, 0x60c640L, 0x42c640L, 0x22c640L, 0x62c440L, 0x62c240L, 0x628640L, 0x624640L, 0x62c600L, 0x2c640L, 0x62c040L, 0x620640L));
		aList.add(a1);


		int k = 0;
		
		print("Starting cleaning\n");
		for(int i = 0; i < aList.size(); i++)
		{
			print("Array " + i + " size " + aList.get(i).size() + "\n");
		}
		
		// Check if all opcodes are real and remove not read ones
		for (int i = 0; i <aList.size(); i++)		
		{
			for(int j = 0; j < aList.get(i).size(); j++)
			{
				Address current_instruction = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(init_addr);

				clearListing(current_instruction);
				this.setBytes(current_instruction, longToBytes_24bits(aList.get(i).get(j)));
					
				disassemble(current_instruction);
				
				if(getInstructionAt(current_instruction) == null)
				{
					print("Incorrect opcode. Removed\n");
					
					println(HexFormat.of().formatHex(getBytes(current_instruction,3)));
				
					// Remove from everywhere
					aList.get(i).remove(j);
					j--;
					
				}
			}
			
		}
		
		int total = 1;

		for(int i = 0; i < aList.size(); i++)
		{
			total = total * aList.get(i).size(); 
			print("Array " + i + " size " + aList.get(i).size() + "\n");
			
		}
		print("Totl of " + total + " possible values\n");
		
		
		outfile = new FileWriter("emulation_output.txt"); 
		
		// Execute the brute force
		recursive_execute(aList,0, new long[0]);

		outfile.close();

	
	}
}
