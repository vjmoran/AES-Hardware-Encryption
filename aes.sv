/////////////////////////////////////////////
// aes.sv
// HMC E155 16 September 2015
// bchasnov@hmc.edu, David_Harris@hmc.edu
/////////////////////////////////////////////

/////////////////////////////////////////////
// testbench
//   Tests AES with cases from FIPS-197 appendix
/////////////////////////////////////////////

module testbench();
    logic clk, load, done, sck, sdi, sdo;
    logic [127:0] key, plaintext, cyphertext, expected;
	 logic [255:0] comb;
    logic [8:0] i;
    
    // device under test
    aes dut(clk, sck, sdi, sdo, load, done);
    
    // test case
    initial begin   
	// test case from FIPS-197 Appendix A.1, B
        key       <= 128'h2B7E151628AED2A6ABF7158809CF4F3C;
        plaintext <= 128'h3243F6A8885A308D313198A2E0370734;
        expected  <= 128'h3925841D02DC09FBDC118597196A0B32;

// Alternate test case from Appendix C.1
//      key       <= 128'h000102030405060708090A0B0C0D0E0F;
//      plaintext <= 128'h00112233445566778899AABBCCDDEEFF;
//      expected  <= 128'h69C4E0D86A7B0430D8CDB78070B4C55A;
    end
    
    // generate clock and load signals
    initial 
        forever begin
            clk = 1'b0; #5;
            clk = 1'b1; #5;
        end
        
    initial begin
      i = 0;
      load = 1'b1;
    end 
    
	assign comb = {plaintext, key};
    // shift in test vectors, wait until done, and shift out result
    always @(posedge clk) begin
      if (i == 256) load = 1'b0;
      if (i<256) begin
        #1; sdi = comb[255-i];
        #1; sck = 1; #5; sck = 0;
        i = i + 1;
      end else if (done && i < 384) begin
        #1; sck = 1; 
        #1; cyphertext[383-i] = sdo;
        #4; sck = 0;
        i = i + 1;
      end else if (i == 384) begin
            if (cyphertext == expected)
                $display("Testbench ran successfully");
            else $display("Error: cyphertext = %h, expected %h",
                cyphertext, expected);
            $stop();
      end
    end
    
endmodule


/////////////////////////////////////////////
// aes
//   Top level module with SPI interface and SPI core
/////////////////////////////////////////////

module aes(input  logic clk,
           input  logic sck, 
           input  logic sdi,
           output logic sdo,
           input  logic load,
           output logic done);
                    
    logic [127:0] key, plaintext, cyphertext;
            
    aes_spi spi(sck, sdi, sdo, done, key, plaintext, cyphertext);   
    aes_core core(clk, load, key, plaintext, done, cyphertext);
endmodule

/////////////////////////////////////////////
// aes_spi
//   SPI interface.  Shifts in key and plaintext
//   Captures ciphertext when done, then shifts it out
//   Tricky cases to properly change sdo on negedge clk
/////////////////////////////////////////////

module aes_spi(input  logic sck, 
               input  logic sdi,
               output logic sdo,
               input  logic done,
               output logic [127:0] key, plaintext,
               input  logic [127:0] cyphertext);

    logic         sdodelayed, wasdone;
    logic [127:0] cyphertextcaptured;
               
    // assert load
    // apply 256 sclks to shift in key and plaintext, starting with plaintext[0]
    // then deassert load, wait until done
    // then apply 128 sclks to shift out cyphertext, starting with cyphertext[0]
    always_ff @(posedge sck)
        if (!wasdone)  {cyphertextcaptured, plaintext, key} = {cyphertext, plaintext[126:0], key, sdi};
        else           {cyphertextcaptured, plaintext, key} = {cyphertextcaptured[126:0], plaintext, key, sdi}; 
    
    // sdo should change on the negative edge of sck
    always_ff @(negedge sck) begin
        wasdone = done;
        sdodelayed = cyphertextcaptured[126];
    end
    
    // when done is first asserted, shift out msb before clock edge
    assign sdo = (done & !wasdone) ? cyphertext[127] : sdodelayed;
endmodule

/////////////////////////////////////////////
// aes_core
//   top level AES encryption module
//   when load is asserted, takes the current key and plaintext
//   generates cyphertext and asserts done when complete 11 cycles later
// 
//   See FIPS-197 with Nk = 4, Nb = 4, Nr = 10
//
//   The key and message are 128-bit values packed into an array of 16 bytes as
//   shown below
//        [127:120] [95:88] [63:56] [31:24]     S0,0    S0,1    S0,2    S0,3
//        [119:112] [87:80] [55:48] [23:16]     S1,0    S1,1    S1,2    S1,3
//        [111:104] [79:72] [47:40] [15:8]      S2,0    S2,1    S2,2    S2,3
//        [103:96]  [71:64] [39:32] [7:0]       S3,0    S3,1    S3,2    S3,3
//
//   Equivalently, the values are packed into four words as given
//        [127:96]  [95:64] [63:32] [31:0]      w[0]    w[1]    w[2]    w[3]
/////////////////////////////////////////////

module aes_core(input  logic         clk, 
                input  logic         load,
                input  logic [127:0] key, 
                input  logic [127:0] plaintext, 
                output logic         done, 
                output logic [127:0] cyphertext);

	 logic last;
	 logic [127:0] oldkey, newkey, in, out;
	 logic [3:0] count;
	 logic [127:0] first;
	 	
	 keyExpansion	k(count, oldkey, newkey);
	 firstRound		i(key, plaintext, first);
	 round			r(clk,last,newkey,in,out);
	 
	 assign last = (count == 11);
	 
	 always_ff@(posedge clk) begin
		if (load) begin
			// initialize counter and set done and last bits low
			count = 1;
			done = 0;
			// first round: input to key expansion is key
			//					 input to cipher is plaintext ^ key
			oldkey <= key;
			in <= first;
			count++;
		end
		else if (count <= 11 & count > 0) begin
			// following rounds: input to key expansion is previous round key
			//							input to round is previous output
			oldkey <= newkey;
			in <= out;
			if (count == 11) count = 0;
			else if (count <= 10) count++;
			if (count == 11) done = 1;
			if (last) cyphertext <= out;
		end
	end
endmodule

/////////////////////////////////////////////
// keyExpansion
//   performs a key expansion on cipher key
//	  generates a key schedule
/////////////////////////////////////////////

module keyExpansion(input logic [3:0] round,
						  input  logic [127:0] prevkey,
                    output logic [127:0] nextkey);

	logic [31:0] temp, subrcon, rotated, subbed;
	logic [32:0] rconi, rcon;
	
	assign rconi = 32'b00000000100000000000000000000000;
	
	rotWord rot(temp, rotated);
	subWord sub(rotated, subbed);
	
	always_comb begin
		temp = prevkey[31:0];
		if (round == 10)	rcon = 452984832;
		else if (round == 11) rcon = 905969664;
		else rcon = rconi << (round-1);
		subrcon = subbed ^ rcon;
		nextkey[127:96] = prevkey[127:96] ^ subrcon;
		nextkey[95:64] = prevkey[95:64] ^ nextkey[127:96];
		nextkey[63:32] = prevkey[63:32] ^ nextkey[95:64];
		nextkey[31:0] = prevkey[31:0] ^ nextkey[63:32];
	end
endmodule

/////////////////////////////////////////////
// rotWord
//   performs a cyclical permutation to a word
/////////////////////////////////////////////

module rotWord(input  logic [31:0] a,
               output logic [31:0] y);
	
	always_comb begin
		 y = a << 8;
		 y += (a >> 24);
	end
endmodule

/////////////////////////////////////////////
// subWord
//   applies S-box to 4 bytes of a word
/////////////////////////////////////////////

module subWord(input  logic [31:0] a,
               output logic [31:0] y);

	sbox	sb1(a[31:24], y[31:24]);
	sbox	sb2(a[23:16], y[23:16]);
	sbox	sb3(a[15:8], y[15:8]);
	sbox	sb4(a[7:0], y[7:0]);
endmodule

/////////////////////////////////////////////
// firstRound
//   XOR key and plaintext
/////////////////////////////////////////////

module firstRound(input  logic [127:0] key, 
						input  logic [127:0] a,
                  output logic [127:0] y);

		assign y = a ^ key;
endmodule

/////////////////////////////////////////////
// round
//   performs a round of the encryption
/////////////////////////////////////////////

module round(input  logic         clk,
				 input  logic			 last,
				 input  logic [127:0] key, 
				 input  logic [127:0] a,
				 output logic [127:0] y);
	
	logic [127:0] sub, shift, mix;
	
	subBytes		sb(a, sub);
	shiftRows	sr(sub, shift);
	mixcolumns	mc(shift, mix);
	
	always_comb
		if (!last)	y = mix ^ key;
		else			y = shift ^ key;
endmodule

/////////////////////////////////////////////
// subBytes
//   applies S-box to 16 bytes of an array
/////////////////////////////////////////////

module subBytes(input  logic [127:0] a,
                output logic [127:0] y);

	subWord	sw1(a[127:96], y[127:96]);
	subWord	sw2(a[95:64], y[95:64]);
	subWord	sw3(a[63:32], y[63:32]);
	subWord	sw4(a[31:0], y[31:0]);
	
endmodule

/////////////////////////////////////////////
// sbox
//   Infamous AES byte substitutions with magic numbers
//   Section 5.1.1, Figure 7
/////////////////////////////////////////////

module sbox(input  logic [7:0] a,
            output logic [7:0] y);
            
  // sbox implemented as a ROM
  logic [7:0] sbox[0:255];

  initial   $readmemh("sbox.txt", sbox);
  assign y = sbox[a];
endmodule

/////////////////////////////////////////////
// shiftRows
// 	cyclically shifts bits in last 3 rows
/////////////////////////////////////////////

module shiftRows(input  logic [127:0] a,
                 output logic [127:0] y);

	logic [31:0] second, third, fourth;	

	// first row
	assign y[127:120] = a[127:120];
	assign y[95:88] = a[95:88];
	assign y[63:56] = a[63:56];
	assign y[31:24] = a[31:24];
	
	// second row
	assign y[119:112] = a[87:80];
	assign y[87:80] = a[55:48];
	assign y[55:48] = a[23:16];
	assign y[23:16] = a[119:112];
	
	// third row
	assign y[111:104] = a[47:40];
	assign y[79:72] = a[15:8];
	assign y[47:40] = a[111:104];
	assign y[15:8] = a[79:72];
	
	// fourth row
	assign y[103:96] = a[7:0];
	assign y[71:64] = a[103:96];
	assign y[39:32] = a[71:64];
	assign y[7:0] = a[39:32];
endmodule

/////////////////////////////////////////////
// mixcolumns
//   Even funkier action on columns
//   Section 5.1.3, Figure 9
//   Same operation performed on each of four columns
/////////////////////////////////////////////

module mixcolumns(input  logic [127:0] a,
                  output logic [127:0] y);

	mixcolumn mc0(a[127:96], y[127:96]);
	mixcolumn mc1(a[95:64],  y[95:64]);
	mixcolumn mc2(a[63:32],  y[63:32]);
	mixcolumn mc3(a[31:0],   y[31:0]);
endmodule

/////////////////////////////////////////////
// mixcolumn
//   Perform Galois field operations on bytes in a column
//   See EQ(4) from E. Ahmed et al, Lightweight Mix Columns Implementation for AES, AIC09
//   for this hardware implementation
/////////////////////////////////////////////

module mixcolumn(input  logic [31:0] a,
                 output logic [31:0] y);
                      
	logic [7:0] a0, a1, a2, a3, y0, y1, y2, y3, t0, t1, t2, t3, tmp;

	assign {a0, a1, a2, a3} = a;
	assign tmp = a0 ^ a1 ^ a2 ^ a3;

	galoismult gm0(a0^a1, t0);
	galoismult gm1(a1^a2, t1);
	galoismult gm2(a2^a3, t2);
	galoismult gm3(a3^a0, t3);

	assign y0 = a0 ^ tmp ^ t0;
	assign y1 = a1 ^ tmp ^ t1;
	assign y2 = a2 ^ tmp ^ t2;
	assign y3 = a3 ^ tmp ^ t3;
	assign y = {y0, y1, y2, y3};    
endmodule

/////////////////////////////////////////////
// galoismult
//   Multiply by x in GF(2^8) is a left shift
//   followed by an XOR if the result overflows
//   Uses irreducible polynomial x^8+x^4+x^3+x+1 = 00011011
/////////////////////////////////////////////

module galoismult(input  logic [7:0] a,
                  output logic [7:0] y);

    logic [7:0] ashift;
    
    assign ashift = {a[6:0], 1'b0};
    assign y = a[7] ? (ashift ^ 8'b00011011) : ashift;
endmodule

