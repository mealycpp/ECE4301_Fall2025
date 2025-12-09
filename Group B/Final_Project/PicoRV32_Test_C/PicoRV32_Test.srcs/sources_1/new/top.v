// top.v - PicoRV32 + 64KB BRAM + UART TX + Buttons (Artix-7)
// MMIO map:
//   0x1000_0000 : UART TX (W: data byte; R: {busy,31'b0})
//   0x1000_0004 : CONTINUE button (R: {31'b0, pressed})
//   0x1000_0008 : SKIP     button (R: {31'b0, pressed})

module top (
  input  wire clk_100mhz,
  input  wire rst_n,           // active-low reset
  input  wire btn_continue,
  input  wire btn_skip,
  output wire uart_tx
);

  // ---------------- Clock / reset ----------------
  wire clk = clk_100mhz;
  reg [2:0] rst_sync;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) rst_sync <= 3'b111;
    else        rst_sync <= {rst_sync[1:0], 1'b0};
  end
  wire reset = rst_sync[2];

  // ---------------- PicoRV32 bus ----------------
  wire        mem_valid, mem_instr;
  reg         mem_ready;
  wire [31:0] mem_addr, mem_wdata;
  wire [3:0]  mem_wstrb;
  reg  [31:0] mem_rdata;

  // Extra ports present in the 27-port picorv32
  wire        trap;
  wire        mem_la_read, mem_la_write;
  wire [31:0] mem_la_addr, mem_la_wdata;
  wire [3:0]  mem_la_wstrb;
  // PCPI (tie inputs inactive)
  wire        pcpi_valid;
  wire [31:0] pcpi_insn, pcpi_rs1, pcpi_rs2;
  wire        pcpi_wr = 1'b0;
  wire [31:0] pcpi_rd = 32'h0;
  wire        pcpi_wait = 1'b0;
  wire        pcpi_ready = 1'b0;
  // IRQ/EIO/trace
  wire [31:0] eoi;
  wire        trace_valid;
  wire [35:0] trace_data;

  picorv32 #(
    .ENABLE_MUL      (1),
    .ENABLE_DIV      (1),
    .BARREL_SHIFTER  (1),
    .COMPRESSED_ISA  (1),
    .ENABLE_COUNTERS (1),
    .CATCH_MISALIGN  (1),
    .CATCH_ILLINSN   (1),
    .ENABLE_IRQ      (1),
    .ENABLE_IRQ_QREGS(1),
    .PROGADDR_RESET  (32'h8000_0000),
    .PROGADDR_IRQ    (32'h8000_0100)
  ) cpu (
    .clk          (clk),
    .resetn       (!reset),
    .trap         (trap),

    .mem_valid    (mem_valid),
    .mem_instr    (mem_instr),
    .mem_ready    (mem_ready),
    .mem_addr     (mem_addr),
    .mem_wdata    (mem_wdata),
    .mem_wstrb    (mem_wstrb),
    .mem_rdata    (mem_rdata),

    // look-ahead interface: unused
    .mem_la_read  (mem_la_read),
    .mem_la_write (mem_la_write),
    .mem_la_addr  (mem_la_addr),
    .mem_la_wdata (mem_la_wdata),
    .mem_la_wstrb (mem_la_wstrb),

    // PCPI: unused
    .pcpi_valid   (pcpi_valid),
    .pcpi_insn    (pcpi_insn),
    .pcpi_rs1     (pcpi_rs1),
    .pcpi_rs2     (pcpi_rs2),
    .pcpi_wr      (pcpi_wr),
    .pcpi_rd      (pcpi_rd),
    .pcpi_wait    (pcpi_wait),
    .pcpi_ready   (pcpi_ready),

    .irq          (32'b0),
    .eoi          (eoi),

    // instruction trace: unused
    .trace_valid  (trace_valid),
    .trace_data   (trace_data)
  );

  // ---------------- Address decode ----------------
  localparam [31:0] BRAM_BASE     = 32'h8000_0000;
  localparam [31:0] BRAM_MASK     = 32'hFFFF_0000; // 64 KiB window

  localparam [31:0] UART_ADDR     = 32'h1000_0000;
  localparam [31:0] BTN_CONT_ADDR = 32'h1000_0004;
  localparam [31:0] BTN_SKIP_ADDR = 32'h1000_0008;

  // Live decode (used only when latching a new request)
  wire hit_bram = ((mem_addr & BRAM_MASK) == BRAM_BASE);
  wire hit_uart = (mem_addr == UART_ADDR);
  wire hit_cbtn = (mem_addr == BTN_CONT_ADDR);
  wire hit_sbtn = (mem_addr == BTN_SKIP_ADDR);

  // ---------------- 64 KiB BRAM (Xilinx-friendly template) ----------------
  localparam integer MEM_BYTES = 32'd65536;
  localparam integer MEM_WORDS = MEM_BYTES / 4;
  (* ram_style="block" *) reg [31:0] bram [0:MEM_WORDS-1];

  // Registered address/data/WE for BRAM
  reg  [13:0] bram_addr_r;
  reg  [31:0] bram_wdata_r;
  reg  [3:0]  bram_wstrb_r;
  reg  [31:0] bram_rdata_r;

  always @(posedge clk) begin
    // Synchronous read (address registered)
    bram_rdata_r <= bram[bram_addr_r];

    // Synchronous write with byte enables
    if (bram_wstrb_r[0]) bram[bram_addr_r][7:0]   <= bram_wdata_r[7:0];
    if (bram_wstrb_r[1]) bram[bram_addr_r][15:8]  <= bram_wdata_r[15:8];
    if (bram_wstrb_r[2]) bram[bram_addr_r][23:16] <= bram_wdata_r[23:16];
    if (bram_wstrb_r[3]) bram[bram_addr_r][31:24] <= bram_wdata_r[31:24];
  end

  initial begin
    $readmemh("prog.hex", bram);
  end

  // ---------------- UART TX (115200 @ 100 MHz) ----------------
  localparam integer BAUD_DIV = 100_000_000 / 115200;
  reg        uart_start;
  reg  [7:0] uart_data;
  wire       uart_busy;

  uart_tx_min #(.DIV(BAUD_DIV)) UTX (
    .clk   (clk),
    .rst   (reset),
    .start (uart_start),
    .data  (uart_data),
    .tx    (uart_tx),
    .busy  (uart_busy)
  );

  // ---------------- Buttons (sync + tiny debounce) ----------------
  // 2FF sync with reset
  reg [1:0] cont_sync, skip_sync;
  always @(posedge clk) begin
    if (reset) begin
      cont_sync <= 2'b00;
      skip_sync <= 2'b00;
    end else begin
      cont_sync <= {cont_sync[0], btn_continue};
      skip_sync <= {skip_sync[0], btn_skip};
    end
  end

  // very small debouncer: requires N consecutive 1s to assert
  localparam integer DBITS = 16;
  reg [DBITS-1:0] cont_db, skip_db;
  always @(posedge clk) begin
    if (reset) begin
      cont_db <= {DBITS{1'b0}};
      skip_db <= {DBITS{1'b0}};
    end else begin
      cont_db <= {cont_db[DBITS-2:0], cont_sync[1]};
      skip_db <= {skip_db[DBITS-2:0], skip_sync[1]};
    end
  end

  wire cont_pressed = &cont_db;
  wire skip_pressed = &skip_db;

  wire [31:0] btn_cont_rd = {31'b0, cont_pressed};
  wire [31:0] btn_skip_rd = {31'b0, skip_pressed};

  // =================================================================
  //                 SIMPLE SERIALIZED BUS (ONE REQ AT A TIME)
  // =================================================================
  localparam DEV_NONE = 2'd0, DEV_BRAM = 2'd1, DEV_UART = 2'd2, DEV_BTN = 2'd3;

  reg        req_active;
  reg [1:0]  req_dev;
  reg        req_is_write;
  reg [3:0]  req_wstrb;
  reg [31:0] req_addr;
  reg [31:0] req_wdata;
  reg        req_btn_is_cont;
  reg        bram_read_pending;  // one-cycle BRAM read pipeline

  wire       req_start = mem_valid && !req_active;

  // Latch/advance request and side effects
  always @(posedge clk or posedge reset) begin
    if (reset) begin
      req_active        <= 1'b0;
      req_dev           <= DEV_NONE;
      req_is_write      <= 1'b0;
      req_wstrb         <= 4'h0;
      req_addr          <= 32'h0;
      req_wdata         <= 32'h0;
      req_btn_is_cont   <= 1'b0;
      bram_read_pending <= 1'b0;
      // BRAM ctrl regs
      bram_addr_r       <= 14'h0;
      bram_wdata_r      <= 32'h0;
      bram_wstrb_r      <= 4'h0;
    end else begin
      // default: no BRAM write unless we set wstrb_r this cycle
      bram_wstrb_r <= 4'h0;
      
      // auto-advance the 1-cycle BRAM read pipeline
      if (bram_read_pending) bram_read_pending <= 1'b0;

      // Start a new request
      if (req_start) begin
        req_active   <= 1'b1;
        req_addr     <= mem_addr;
        req_wdata    <= mem_wdata;
        req_wstrb    <= mem_wstrb;
        req_is_write <= |mem_wstrb;

        if (hit_bram) begin
          req_dev     <= DEV_BRAM;
          // Register BRAM address/data for both read and write
          bram_addr_r  <= mem_addr[15:2];
          bram_wdata_r <= mem_wdata;
          bram_wstrb_r <= 4'h0;                 // write will be armed on complete
          // Arm one-cycle read reply if it's a read
          bram_read_pending <= (|mem_wstrb) ? 1'b0 : 1'b1;
        end
        else if (hit_uart) begin
          req_dev <= DEV_UART;
        end
        else if (hit_cbtn) begin
          req_dev         <= DEV_BTN;
          req_btn_is_cont <= 1'b1;
        end
        else if (hit_sbtn) begin
          req_dev         <= DEV_BTN;
          req_btn_is_cont <= 1'b0;
        end
        else begin
          req_dev <= DEV_NONE; // unmapped
        end
      end

      // UART: pulse start only when accepting a write
      uart_start <= 1'b0;
      if (req_active && (req_dev==DEV_UART) && req_is_write && !uart_busy) begin
        uart_data  <= req_wdata[7:0];
        uart_start <= 1'b1;
      end

      // BRAM: when completing a WRITE, drive write enables this cycle
      if (req_active && (req_dev==DEV_BRAM) && req_is_write && mem_ready) begin
        bram_wstrb_r <= req_wstrb; // does the synchronous write in BRAM block
      end

      // finish request when we ack it
      if (req_active && mem_ready) begin
        req_active        <= 1'b0;
        req_dev           <= DEV_NONE;
        bram_read_pending <= 1'b0; // read consumed
      end
    end
  end

  // ---------------- Drive mem_ready / mem_rdata from latched request ----------------
  wire [31:0] uart_status = {31'b0, uart_busy};

  always @(*) begin
    mem_ready = 1'b0;
    mem_rdata = 32'h0;

    if (!req_active) begin
      mem_ready = 1'b0;
    end else begin
      case (req_dev)
        DEV_BRAM: begin
          if (req_is_write) begin
            // immediate completion for writes (write occurs on this clk edge)
            mem_ready = 1'b1;
            mem_rdata = 32'h0;
          end else begin
            // BRAM read completes one cycle after request
            mem_ready = (bram_read_pending == 1'b0);
            mem_rdata = bram_rdata_r;
          end
        end
        DEV_UART: begin
          if (req_is_write) begin
            mem_ready = !uart_busy;   // stall until TX can take the byte
            mem_rdata = 32'h0;
          end else begin
            mem_ready = 1'b1;
            mem_rdata = uart_status;
          end
        end
        DEV_BTN: begin
          mem_ready = 1'b1;
          mem_rdata = req_btn_is_cont ? btn_cont_rd : btn_skip_rd;
        end
        default: begin
          mem_ready = 1'b1;           // unmapped -> read zeros
          mem_rdata = 32'h0;
        end
      endcase
    end
  end

endmodule
