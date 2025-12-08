`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// poseidon_core.v
//
// Simple Poseidon-style permutation core (t=3, 32-bit words, x^5 S-box)
//
// Interface:
//   - Assert start for one clock with in0/in1/in2 valid.
//   - 'busy' goes high while core is working.
//   - After 8 rounds (8 cycles), 'done' pulses high for 1 cycle
//     and out0/out1/out2 hold the permutation result.
//
//////////////////////////////////////////////////////////////////////////////////

module poseidon_core
(
    input  wire         clk,
    input  wire         rst_n,   // active-low synchronous reset

    input  wire         start,   // one-cycle start pulse
    input  wire [31:0]  in0,
    input  wire [31:0]  in1,
    input  wire [31:0]  in2,

    output reg  [31:0]  out0,
    output reg  [31:0]  out1,
    output reg  [31:0]  out2,
    output reg          done,    // 1-cycle pulse when permutation completes
    output reg          busy     // high while running
);

    // -----------------------------------------------------------------------
    // Parameters
    // -----------------------------------------------------------------------
    localparam integer N_ROUNDS = 8;
    localparam integer R_F_HALF = 2;  // 2 full rounds at start, 2 at end

    // Internal state
    reg [31:0] st0, st1, st2;
    reg [3:0]  round_ctr;

    // -----------------------------------------------------------------------
    // S-box: x^5 in Z_2^32 (wrap-around 32-bit multiply)
    // -----------------------------------------------------------------------
    function [31:0] sbox;
        input [31:0] x;
        reg   [31:0] x2, x4;
    begin
        x2   = x * x;
        x4   = x2 * x2;
        sbox = x4 * x;
    end
    endfunction

    // -----------------------------------------------------------------------
    // Round constants (3 per round, 8 rounds)
    // These match what you're using in software.
    // -----------------------------------------------------------------------
    function [31:0] rc0;
        input [3:0] r;
    begin
        case (r)
            4'd0: rc0 = 32'h243F6A88;
            4'd1: rc0 = 32'h85A308D3;
            4'd2: rc0 = 32'h13198A2E;
            4'd3: rc0 = 32'h03707344;
            4'd4: rc0 = 32'hA4093822;
            4'd5: rc0 = 32'h299F31D0;
            4'd6: rc0 = 32'h082EFA98;
            4'd7: rc0 = 32'hEC4E6C89;
            default: rc0 = 32'h0;
        endcase
    end
    endfunction

    function [31:0] rc1;
        input [3:0] r;
    begin
        case (r)
            4'd0: rc1 = 32'h452821E6;
            4'd1: rc1 = 32'h38D01377;
            4'd2: rc1 = 32'hBE5466CF;
            4'd3: rc1 = 32'h34E90C6C;
            4'd4: rc1 = 32'hC0AC29B7;
            4'd5: rc1 = 32'hC97C50DD;
            4'd6: rc1 = 32'h3F84D5B5;
            4'd7: rc1 = 32'hB5470917;
            default: rc1 = 32'h0;
        endcase
    end
    endfunction

    function [31:0] rc2;
        input [3:0] r;
    begin
        case (r)
            4'd0: rc2 = 32'h9216D5D9;
            4'd1: rc2 = 32'h8979FB1B;
            4'd2: rc2 = 32'hD1310BA6;
            4'd3: rc2 = 32'h98DFB5AC;
            4'd4: rc2 = 32'h2FFD72DB;
            4'd5: rc2 = 32'hD01ADFB7;
            4'd6: rc2 = 32'hB8E1AFED;
            4'd7: rc2 = 32'h6A267E96;
            default: rc2 = 32'h0;
        endcase
    end
    endfunction

    // -----------------------------------------------------------------------
    // Full vs partial rounds
    // Full S-box on all 3 words for first 2 and last 2 rounds,
    // only first state element goes through S-box in middle 4 rounds.
    // -----------------------------------------------------------------------
    wire full_round =
        (round_ctr < R_F_HALF) ||
        (round_ctr >= (N_ROUNDS - R_F_HALF));

    // -----------------------------------------------------------------------
    // Combinational next-state for one Poseidon round
    // -----------------------------------------------------------------------
    reg [31:0] a0, a1, a2;  // after add round constants
    reg [31:0] s0, s1, s2;  // after S-box
    reg [31:0] m0, m1, m2;  // after MDS

    always @* begin
        // 1) Add round constants
        a0 = st0 + rc0(round_ctr);
        a1 = st1 + rc1(round_ctr);
        a2 = st2 + rc2(round_ctr);

        // 2) Apply S-box
        if (full_round) begin
            s0 = sbox(a0);
            s1 = sbox(a1);
            s2 = sbox(a2);
        end else begin
            // partial round: only first element non-linear
            s0 = sbox(a0);
            s1 = a1;
            s2 = a2;
        end

        // 3) Apply 3x3 MDS matrix: [2 1 1; 1 2 1; 1 1 2] mod 2^32
        m0 = (s0 << 1) + s1 + s2;           // 2*s0 + s1 + s2
        m1 = s0 + (s1 << 1) + s2;           // s0 + 2*s1 + s2
        m2 = s0 + s1 + (s2 << 1);           // s0 + s1 + 2*s2
    end

    // -----------------------------------------------------------------------
    // Sequencing: load on start, then 8 rounds, then done
    // -----------------------------------------------------------------------
    always @(posedge clk) begin
        if (!rst_n) begin
            st0        <= 32'd0;
            st1        <= 32'd0;
            st2        <= 32'd0;
            round_ctr  <= 4'd0;
            out0       <= 32'd0;
            out1       <= 32'd0;
            out2       <= 32'd0;
            busy       <= 1'b0;
            done       <= 1'b0;
        end else begin
            done <= 1'b0;  // default

            if (start && !busy) begin
                // Load input state and start permutation
                st0       <= in0;
                st1       <= in1;
                st2       <= in2;
                round_ctr <= 4'd0;
                busy      <= 1'b1;
            end else if (busy) begin
                // Perform one round per cycle
                st0 <= m0;
                st1 <= m1;
                st2 <= m2;

                if (round_ctr == (N_ROUNDS - 1)) begin
                    // Last round: produce output and signal done
                    out0      <= m0;
                    out1      <= m1;
                    out2      <= m2;
                    busy      <= 1'b0;
                    done      <= 1'b1;  // one-cycle pulse
                end

                round_ctr <= round_ctr + 1'b1;
            end
        end
    end

endmodule
