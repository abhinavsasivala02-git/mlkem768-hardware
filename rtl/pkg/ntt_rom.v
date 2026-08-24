/*
 * Copyright (C) 2026
 * Author: Abhinav S <abhinavsasivala02@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

//============================================================================
// NTT Zeta ROM - Precomputed twiddle factors for ML-KEM NTT
// 128 entries of zeta^{BitRev7(i)} in Montgomery form (xR mod q)
// zeta = 17 (primitive 256th root of unity mod q=3329)
// R = 2^16 mod q = 2285
//
// Generated from FIPS-203 Appendix A: zetas[k] = 17^BitRev7(k) mod q.
// Stored as signed 16-bit for direct use in Montgomery multiplication.
// Verified: rom[k] * Rinv mod q == 17^BitRev7(k) for all k.
//
// SYNTHESIS-SAFE: No initial block. Uses combinational case + registered
// output so Cadence Genus infers BRAM or DFF-bank automatically.
//============================================================================
module ntt_rom (
    input  wire              clk,
    input  wire [6:0]        addr,    // 0..127
    output reg  signed [15:0] zeta
);

    // Combinational ROM - pure case statement, synthesis-safe
    reg signed [15:0] zeta_comb;

    always @(*) begin
        case (addr)
            7'd0:  zeta_comb = -16'sd1044;
            7'd1:  zeta_comb = -16'sd758;
            7'd2:  zeta_comb = -16'sd359;
            7'd3:  zeta_comb = -16'sd1517;
            7'd4:  zeta_comb =  16'sd1493;
            7'd5:  zeta_comb =  16'sd1422;
            7'd6:  zeta_comb =  16'sd287;
            7'd7:  zeta_comb =  16'sd202;
            7'd8:  zeta_comb = -16'sd171;
            7'd9:  zeta_comb =  16'sd622;
            7'd10:  zeta_comb =  16'sd1577;
            7'd11:  zeta_comb =  16'sd182;
            7'd12:  zeta_comb =  16'sd962;
            7'd13:  zeta_comb = -16'sd1202;
            7'd14:  zeta_comb = -16'sd1474;
            7'd15:  zeta_comb =  16'sd1468;
            7'd16:  zeta_comb =  16'sd573;
            7'd17:  zeta_comb = -16'sd1325;
            7'd18:  zeta_comb =  16'sd264;
            7'd19:  zeta_comb =  16'sd383;
            7'd20:  zeta_comb = -16'sd829;
            7'd21:  zeta_comb =  16'sd1458;
            7'd22:  zeta_comb = -16'sd1602;
            7'd23:  zeta_comb = -16'sd130;
            7'd24:  zeta_comb = -16'sd681;
            7'd25:  zeta_comb =  16'sd1017;
            7'd26:  zeta_comb =  16'sd732;
            7'd27:  zeta_comb =  16'sd608;
            7'd28:  zeta_comb = -16'sd1542;
            7'd29:  zeta_comb =  16'sd411;
            7'd30:  zeta_comb = -16'sd205;
            7'd31:  zeta_comb = -16'sd1571;
            7'd32:  zeta_comb =  16'sd1223;
            7'd33:  zeta_comb =  16'sd652;
            7'd34:  zeta_comb = -16'sd552;
            7'd35:  zeta_comb =  16'sd1015;
            7'd36:  zeta_comb = -16'sd1293;
            7'd37:  zeta_comb =  16'sd1491;
            7'd38:  zeta_comb = -16'sd282;
            7'd39:  zeta_comb = -16'sd1544;
            7'd40:  zeta_comb =  16'sd516;
            7'd41:  zeta_comb = -16'sd8;
            7'd42:  zeta_comb = -16'sd320;
            7'd43:  zeta_comb = -16'sd666;
            7'd44:  zeta_comb = -16'sd1618;
            7'd45:  zeta_comb = -16'sd1162;
            7'd46:  zeta_comb =  16'sd126;
            7'd47:  zeta_comb =  16'sd1469;
            7'd48:  zeta_comb = -16'sd853;
            7'd49:  zeta_comb = -16'sd90;
            7'd50:  zeta_comb = -16'sd271;
            7'd51:  zeta_comb =  16'sd830;
            7'd52:  zeta_comb =  16'sd107;
            7'd53:  zeta_comb = -16'sd1421;
            7'd54:  zeta_comb = -16'sd247;
            7'd55:  zeta_comb = -16'sd951;
            7'd56:  zeta_comb = -16'sd398;
            7'd57:  zeta_comb =  16'sd961;
            7'd58:  zeta_comb = -16'sd1508;
            7'd59:  zeta_comb = -16'sd725;
            7'd60:  zeta_comb =  16'sd448;
            7'd61:  zeta_comb = -16'sd1065;
            7'd62:  zeta_comb =  16'sd677;
            7'd63:  zeta_comb = -16'sd1275;
            7'd64:  zeta_comb = -16'sd1103;
            7'd65:  zeta_comb =  16'sd430;
            7'd66:  zeta_comb =  16'sd555;
            7'd67:  zeta_comb =  16'sd843;
            7'd68:  zeta_comb = -16'sd1251;
            7'd69:  zeta_comb =  16'sd871;
            7'd70:  zeta_comb =  16'sd1550;
            7'd71:  zeta_comb =  16'sd105;
            7'd72:  zeta_comb =  16'sd422;
            7'd73:  zeta_comb =  16'sd587;
            7'd74:  zeta_comb =  16'sd177;
            7'd75:  zeta_comb = -16'sd235;
            7'd76:  zeta_comb = -16'sd291;
            7'd77:  zeta_comb = -16'sd460;
            7'd78:  zeta_comb =  16'sd1574;
            7'd79:  zeta_comb =  16'sd1653;
            7'd80:  zeta_comb = -16'sd246;
            7'd81:  zeta_comb =  16'sd778;
            7'd82:  zeta_comb =  16'sd1159;
            7'd83:  zeta_comb = -16'sd147;
            7'd84:  zeta_comb = -16'sd777;
            7'd85:  zeta_comb =  16'sd1483;
            7'd86:  zeta_comb = -16'sd602;
            7'd87:  zeta_comb =  16'sd1119;
            7'd88:  zeta_comb = -16'sd1590;
            7'd89:  zeta_comb =  16'sd644;
            7'd90:  zeta_comb = -16'sd872;
            7'd91:  zeta_comb =  16'sd349;
            7'd92:  zeta_comb =  16'sd418;
            7'd93:  zeta_comb =  16'sd329;
            7'd94:  zeta_comb = -16'sd156;
            7'd95:  zeta_comb = -16'sd75;
            7'd96:  zeta_comb =  16'sd817;
            7'd97:  zeta_comb =  16'sd1097;
            7'd98:  zeta_comb =  16'sd603;
            7'd99:  zeta_comb =  16'sd610;
            7'd100:  zeta_comb =  16'sd1322;
            7'd101:  zeta_comb = -16'sd1285;
            7'd102:  zeta_comb = -16'sd1465;
            7'd103:  zeta_comb =  16'sd384;
            7'd104:  zeta_comb = -16'sd1215;
            7'd105:  zeta_comb = -16'sd136;
            7'd106:  zeta_comb =  16'sd1218;
            7'd107:  zeta_comb = -16'sd1335;
            7'd108:  zeta_comb = -16'sd874;
            7'd109:  zeta_comb =  16'sd220;
            7'd110:  zeta_comb = -16'sd1187;
            7'd111:  zeta_comb = -16'sd1659;
            7'd112:  zeta_comb = -16'sd1185;
            7'd113:  zeta_comb = -16'sd1530;
            7'd114:  zeta_comb = -16'sd1278;
            7'd115:  zeta_comb =  16'sd794;
            7'd116:  zeta_comb = -16'sd1510;
            7'd117:  zeta_comb = -16'sd854;
            7'd118:  zeta_comb = -16'sd870;
            7'd119:  zeta_comb =  16'sd478;
            7'd120:  zeta_comb = -16'sd108;
            7'd121:  zeta_comb = -16'sd308;
            7'd122:  zeta_comb =  16'sd996;
            7'd123:  zeta_comb =  16'sd991;
            7'd124:  zeta_comb =  16'sd958;
            7'd125:  zeta_comb = -16'sd1460;
            7'd126:  zeta_comb =  16'sd1522;
            7'd127:  zeta_comb =  16'sd1628;
            default: zeta_comb = 16'sd0;
        endcase
    end

    // Synchronous registered output - Genus/ASIC infers BRAM or DFF-bank
    always @(posedge clk) begin
        zeta <= zeta_comb;
    end

endmodule
