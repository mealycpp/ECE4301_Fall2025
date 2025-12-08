`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// poseidon_accel_axi_lite.v
//
// AXI4(-Lite style) slave wrapper around poseidon_core.
//
// Register map (byte offsets from POSEIDON_BASE):
//   0x00 : CONTROL/STATUS
//          [0] - start (W; write 1 to start one permutation)
//          [1] - done  (R; 1 when core done, cleared on new start)
//
//   0x10 : INPUT0 (32-bit)
//   0x14 : INPUT1
//   0x18 : INPUT2
//
//   0x30 : OUTPUT0 (32-bit)
//   0x34 : OUTPUT1
//   0x38 : OUTPUT2
//
//////////////////////////////////////////////////////////////////////////////////

module poseidon_accel_axi_lite #
(
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 6   // enough for 0x00..0x3F
)
(
    // AXI4(-Lite) slave interface
    input  wire                         s_axi_aclk,
    input  wire                         s_axi_aresetn,

    // Write address channel
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr,
    input  wire [2:0]                   s_axi_awprot,
    input  wire                         s_axi_awvalid,
    output reg                          s_axi_awready,

    // Write data channel
    input  wire [C_S_AXI_DATA_WIDTH-1:0] s_axi_wdata,
    input  wire [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb,
    input  wire                         s_axi_wvalid,
    output reg                          s_axi_wready,

    // Write response channel
    output reg  [1:0]                   s_axi_bresp,
    output reg                          s_axi_bvalid,
    input  wire                         s_axi_bready,

    // Read address channel
    input  wire [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr,
    input  wire [2:0]                   s_axi_arprot,
    input  wire                         s_axi_arvalid,
    output reg                          s_axi_arready,

    // Read data channel
    output reg  [C_S_AXI_DATA_WIDTH-1:0] s_axi_rdata,
    output reg  [1:0]                   s_axi_rresp,
    output reg                          s_axi_rvalid,
    input  wire                         s_axi_rready
);

    // ------------------------------------------------------------------------
    // Internal address latches
    // ------------------------------------------------------------------------
    reg [C_S_AXI_ADDR_WIDTH-1:0] awaddr_reg;
    reg [C_S_AXI_ADDR_WIDTH-1:0] araddr_reg;

    // ------------------------------------------------------------------------
    // Internal registers
    // ------------------------------------------------------------------------
    reg [31:0] reg_control;   // bit[0]=start (W), bit[1]=done (R)
    reg [31:0] reg_in0;
    reg [31:0] reg_in1;
    reg [31:0] reg_in2;
    reg [31:0] reg_out0;
    reg [31:0] reg_out1;
    reg [31:0] reg_out2;

    reg        start_pulse;

    // ------------------------------------------------------------------------
    // poseidon_core instance
    // ------------------------------------------------------------------------
    wire       core_done;
    wire       core_busy;
    wire [31:0] core_out0, core_out1, core_out2;

    poseidon_core u_poseidon_core (
        .clk   (s_axi_aclk),
        .rst_n (s_axi_aresetn),
        .start (start_pulse),
        .in0   (reg_in0),
        .in1   (reg_in1),
        .in2   (reg_in2),
        .out0  (core_out0),
        .out1  (core_out1),
        .out2  (core_out2),
        .done  (core_done),
        .busy  (core_busy)
    );

    // ------------------------------------------------------------------------
    // AXI WRITE ADDRESS CHANNEL
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_awready <= 1'b0;
            awaddr_reg    <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (!s_axi_awready && s_axi_awvalid && s_axi_wvalid) begin
                s_axi_awready <= 1'b1;
                awaddr_reg    <= s_axi_awaddr;
            end else begin
                s_axi_awready <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------------
    // AXI WRITE DATA CHANNEL
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_wready <= 1'b0;
        end else begin
            if (!s_axi_wready && s_axi_wvalid && s_axi_awvalid) begin
                s_axi_wready <= 1'b1;
            end else begin
                s_axi_wready <= 1'b0;
            end
        end
    end

    // Single-beat write enable
    wire slv_reg_wren = s_axi_awready && s_axi_awvalid &&
                        s_axi_wready  && s_axi_wvalid;

    // ------------------------------------------------------------------------
    // REGISTER WRITE LOGIC
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
                case (awaddr_reg[5:0])  // decode low 6 bits (0x00..0x3F)
                    6'h00: begin
                        // CONTROL write; bit[0] = start
                        if (s_axi_wdata[0]) begin
                            start_pulse <= 1'b1;
                        end
                        // do not overwrite done bit here
                    end
                    6'h10: reg_in0 <= s_axi_wdata;
                    6'h14: reg_in1 <= s_axi_wdata;
                    6'h18: reg_in2 <= s_axi_wdata;
                    default: ;
                endcase
            end

            // On start, clear done flag
            if (start_pulse) begin
                reg_control[1] <= 1'b0;
            end

            // When core finishes, latch outputs and set done flag
            if (core_done) begin
                reg_out0      <= core_out0;
                reg_out1      <= core_out1;
                reg_out2      <= core_out2;
                reg_control[1] <= 1'b1;   // done = 1
            end
        end
    end

    // ------------------------------------------------------------------------
    // AXI WRITE RESPONSE CHANNEL
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_bvalid <= 1'b0;
            s_axi_bresp  <= 2'b00;
        end else begin
            if (slv_reg_wren && !s_axi_bvalid) begin
                // respond OKAY
                s_axi_bvalid <= 1'b1;
                s_axi_bresp  <= 2'b00;
            end else if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end
        end
    end

    // ------------------------------------------------------------------------
    // AXI READ ADDRESS CHANNEL
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_arready <= 1'b0;
            araddr_reg    <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (!s_axi_arready && s_axi_arvalid) begin
                s_axi_arready <= 1'b1;
                araddr_reg    <= s_axi_araddr;
            end else begin
                s_axi_arready <= 1'b0;
            end
        end
    end

    // Single-beat read enable
    wire slv_reg_rden = s_axi_arready && s_axi_arvalid && !s_axi_rvalid;

    // ------------------------------------------------------------------------
    // AXI READ DATA CHANNEL (READ MUX)
    // ------------------------------------------------------------------------
    always @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            s_axi_rvalid <= 1'b0;
            s_axi_rresp  <= 2'b00;
            s_axi_rdata  <= {C_S_AXI_DATA_WIDTH{1'b0}};
        end else begin
            if (slv_reg_rden) begin
                s_axi_rvalid <= 1'b1;
                s_axi_rresp  <= 2'b00; // OKAY

                case (araddr_reg[5:0])
                    6'h00: s_axi_rdata <= {30'd0, reg_control[1], 1'b0}; // [1]=done
                    6'h10: s_axi_rdata <= reg_in0;
                    6'h14: s_axi_rdata <= reg_in1;
                    6'h18: s_axi_rdata <= reg_in2;
                    6'h30: s_axi_rdata <= reg_out0;
                    6'h34: s_axi_rdata <= reg_out1;
                    6'h38: s_axi_rdata <= reg_out2;
                    default: s_axi_rdata <= 32'd0;
                endcase
            end else if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end
        end
    end

endmodule
