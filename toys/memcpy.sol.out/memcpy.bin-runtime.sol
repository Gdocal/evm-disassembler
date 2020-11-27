contract Contract {
    function main() {
        memory[0x40:0x60] = 0x80;
        var var0 = msg.value;

        if (var0) { revert(memory[0x00:0x00]); }

        if (msg.data.length < 0x04) { revert(memory[0x00:0x00]); }

        var0 = msg.data[0x00:0x20] >> 0xe0;

        if (var0 != 0x8b44cef1) { revert(memory[0x00:0x00]); }

        var var1 = 0x00a0;
        var var2 = 0x04;
        var var3 = msg.data.length - var2;

        if (var3 < 0x20) { revert(memory[0x00:0x00]); }

        var temp0 = var2;
        var temp1 = temp0 + var3;
        var3 = temp0;
        var2 = temp1;
        var var4 = var3 + 0x20;
        var var5 = msg.data[var3:var3 + 0x20];

        if (var5 > 0x0100000000) { revert(memory[0x00:0x00]); }

        var temp2 = var3 + var5;
        var5 = temp2;

        if (var5 + 0x20 > var2) { revert(memory[0x00:0x00]); }

        var temp3 = var5;
        var temp4 = msg.data[temp3:temp3 + 0x20]; // d.length
        var5 = temp4;
        var temp5 = var4;
        var4 = temp3 + 0x20;
        var var6 = temp5;

        if ((var5 > 0x0100000000) | (var4 + var5 * 0x20 > var2)) { revert(memory[0x00:0x00]); }

        var2 = var4;
        var3 = var5;
        var4 = 0x00ae;
        var5 = 0x00;
        var6 = var2;
        var var7 = var3; // d.length
        var temp6 = var5;
        var temp7 = storage[temp6]; // storage[0] == data.length
        var temp8 = var7;
        storage[temp6] = temp8; // storage[0] := d.length
        memory[0x00:0x20] = temp6;
        var var8 = keccak256(memory[0x00:0x20]); // & data[0]
        var temp9 = var6;
        var6 = var8 + temp7; // & data[0] + data.length
        var var9 = temp9;

        if (!temp8) {
        label_00EE:
            var temp10 = var6; // & data[0] + data.length
            var6 = 0x00fa;
            var7 = temp10;
            var6 = func_00FE(var7, var8);
            var4 = func_00FA(var5, var6);
            // Error: Could not resolve method call return address!
        } else {
            var temp11 = var7; // d.length
            var temp12 = var9; // & d[0]
            var7 = temp12; // & d[0]
            var9 = var7 + temp11 * 0x20; // & d[0] + d.length * 0x20

            if (var9 <= var7) { goto label_00EE; }

        label_00DC:
            var temp13 = var7; 								  // & d[0]       	 // & d[1]
            var temp14 = var8; 								  // & data[0]  	 // & data[1]
            storage[temp14] = msg.data[temp13:temp13 + 0x20]; // data[0] := d[0] // data[1] := d[1]
            var7 = temp13 + 0x20; 							  // & d[1]  		 // & d[2]
            var8 = temp14 + 0x01; 							  // & data[1] 		 // & data[2]
            var9 = var9; // & d[0] + d.length * 0x20

            if (var9 <= var7) { goto label_00EE; }
            else { goto label_00DC; }
        }
    }

    function func_00FA(var arg0, var arg1) returns (var r0) { return arg0; }

    function func_00FE(var arg0 /* & data[0] + data.length */, var arg1 /* & data[2] */) returns (var r0) {
        var temp0 = arg0; // & data[0] + data.length
        arg0 = 0x0118;
        var temp1 = arg1;
        arg1 = temp0; // & data[0] + data.length
        var var0 = temp1; // & data[2]

        if (arg1 <= var0) { return func_00FA(arg1, var0); }

    label_010D:
        var temp2 = var0;
        storage[temp2] = 0x00;
        var0 = temp2 + 0x01;

        if (arg1 > var0) { goto label_010D; }

        arg0 = func_00FA(arg1, var0);
        // Error: Could not resolve method call return address!
    }
}
