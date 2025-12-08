`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// poseidon_accel_axi_lite_debug
//
// AXI4-Lite peripheral for bring-up.
// - No poseidon_core inside.
// - On write to CONTROL (bit0=1), it immediately copies INPUT0/1/2
//   into OUTPUT0/1/2 and sets DONE bit.
//
// Register map (byte addresses from base):
//   0x00 : CONTROL/STATUS
//          [0] - start (W; write 1 to start)
//          [1] - done  (R; 1 when "core" done, clears on new start)
//
//   0x10 : INPUT0 (32-bit)
//   0x14 : INPUT1
//   0x18 : INPUT2
//
//   0x30 : OUTPUT0 (32-bit)
//   0x34 : OUTPUT1
//   0x38 : OUTPUT2
//////////////////////////////////////////////////////////////////////////////////

module debug_stub_1 #
(
    parameter C_S_AXI_DATA_WIDTH = 32,
    parameter C_S_AXI_ADDR_WIDTH = 6   // enough for 0x00..0x3F
)
(
    // AXI4-Lite slave interface
    input  wire                         s_axi_aclk,
    input  wire                         s_axi_aresetn,

    // write address channel
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr,
    input  wire [2:0]                   s_axi_awprot,
    input  wire                         s_axi_awvalid,
    output wire                         s_axi_awready,

    // write data channel
    input  wire [C_S_AXI_DATA_WIDTH-1:0] s_axi_wdata,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb,
    input  wire                         s_axi_wvalid,
    output wire                         s_axi_wready,

    // write response channel
    output reg  [1:0]                   s_axi_bresp,
    output reg                          s_axi_bvalid,
    input  wire                         s_axi_bready,

    // read address channel
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr,
    input  wire [2:0]                   s_axi_arprot,
    input  wire                         s_axi_arvalid,
    output wire                         s_axi_arready,

    // read data channel
    output reg  [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata,
    output reg  [1:0]                   s_axi_rresp,
    output reg                          s_axi_rvalid,
    input  wire                         s_axi_rready
);

    // ------------------------------------------------------------------------
    // AXI4-Lite handshake registers
    // ------------------------------------------------------------------------
    reg  axi_awready;
    reg  axi_wready;
    reg  axi_arready;
    reg  [C_S_AXI_ADDR_WIDTH-1:0] axi_awaddr;
    reg  [C_S_AXI_ADDR_WIDTH-1:0] axi_araddr;

    assign s_axi_awready = axi_awready;
    assign s_axi_wready  = axi_wready;
    assign s_axi_arready = axi_arready;

    // write address channel
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            axi_awready <= 1'b0;
            axi_awaddr  <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (!axi_awready && s_axi_awvalid && s_axi_wvalid) begin
                axi_awready <= 1'b1;
                axi_awaddr  <= s_axi_awaddr;
            end else begin
                axi_awready <= 1'b0;
            end
        end
    end

    // write data channel
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            axi_wready <= 1'b0;
        end else begin
            if (!axi_wready && s_axi_wvalid && s_axi_awvalid) begin
                axi_wready <= 1'b1;
            end else begin
                axi_wready <= 1'b0;
            end
        end
    end

    // write enable
    wire slv_reg_wren = axi_awready && s_axi_awvalid &&
                        axi_wready  && s_axi_wvalid;

    // read address channel
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            axi_arready <= 1'b0;
            axi_araddr  <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (!axi_arready && s_axi_arvalid) begin
                axi_arready <= 1'b1;
                axi_araddr  <= s_axi_araddr;
            end else begin
                axi_arready <= 1'b0;
            end
        end
    end

    // read enable
    wire slv_reg_rden = axi_arready && s_axi_arvalid && !s_axi_rvalid;

    // ------------------------------------------------------------------------
    // Internal registers
    // ------------------------------------------------------------------------
    reg [31:0] reg_control;   // [0]=start (W-only), [1]=done (R-only)
    reg [31:0] reg_in0;
    reg [31:0] reg_in1;
    reg [31:0] reg_in2;
    reg [31:0] reg_out0;
    reg [31:0] reg_out1;
    reg [31:0] reg_out2;

    reg        start_pulse;

    // ------------------------------------------------------------------------
    // Register write logic
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            reg_control <= 32'd0;
            reg_in0     <= 32'd0;
            reg_in1     <= 32'd0;
            reg_in2     <= 32'd0;
            reg_out0    <= 32'd0;
            reg_out1    <= 32'd0;
            reg_out2    <= 32'd0;
            start_pulse <= 1'b0;
        end else begin
            start_pulse <= 1'b0; // default

            if (slv_reg_wren) begin
                case (axi_awaddr[5:0])
                    6'h00: begin
                        // CONTROL write; bit[0] = start
                        if (s_axi_wdata[0]) begin
                            start_pulse <= 1'b1;
                        end
                        // done bit is read-only
                    end
                    6'h10: reg_in0 <= s_axi_wdata;
                    6'h14: reg_in1 <= s_axi_wdata;
                    6'h18: reg_in2 <= s_axi_wdata;
                    default: ;
                endcase
            end

            // On start, copy inputs to outputs and set DONE
            if (start_pulse) begin
                reg_out0 <= reg_in0;
                reg_out1 <= reg_in1;
                reg_out2 <= reg_in2;

                reg_control[1] <= 1'b1;   // DONE = 1
            end
        end
    end

    // ------------------------------------------------------------------------
    // Write response channel
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_bvalid <= 1'b0;
            s_axi_bresp  <= 2'b00;
        end else begin
            if (axi_awready && s_axi_awvalid &&
                axi_wready  && s_axi_wvalid &&
                !s_axi_bvalid) begin
                s_axi_bvalid <= 1'b1;
                s_axi_bresp  <= 2'b00; // OKAY
            end else if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------------
    // Read data channel
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_rvalid <= 1'b0;
            s_axi_rresp  <= 2'b00;
            s_axi_rdata  <= {C_S_AXI_DATA_WIDTH{1'b0}};
        end else begin
            if (slv_reg_rden) begin
                s_axi_rvalid <= 1'b1;
                s_axi_rresp  <= 2'b00;
    
                case (axi_araddr[5:0])
                    6'h00: s_axi_rdata <= 32'hABCD0000;          // CONTROL
                    6'h10: s_axi_rdata <= 32'h11111111;          // INPUT0
                    6'h14: s_axi_rdata <= 32'h22222222;          // INPUT1
                    6'h18: s_axi_rdata <= 32'h33333333;          // INPUT2
                    6'h30: s_axi_rdata <= 32'h44444444;          // OUTPUT0
                    6'h34: s_axi_rdata <= 32'h55555555;          // OUTPUT1
                    6'h38: s_axi_rdata <= 32'h66666666;          // OUTPUT2
                    default: s_axi_rdata <= 32'hDEADDEAD;
                endcase
            end else if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end
        end
    end

endmodule
