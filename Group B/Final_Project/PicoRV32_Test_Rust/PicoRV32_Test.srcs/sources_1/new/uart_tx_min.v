// ------------------------------------------------------------------
// Minimal UART TX: 8N1, LSB first, 'DIV' clocks per bit
// ------------------------------------------------------------------
module uart_tx_min #(parameter integer DIV = 868) (
  input  wire clk, rst,
  input  wire start,
  input  wire [7:0] data,
  output reg  tx,
  output reg  busy
);
  reg [15:0] cnt;
  reg [3:0]  bitpos;
  reg [7:0]  sh;

  always @(posedge clk) begin
    if (rst) begin
      tx <= 1'b1; busy <= 1'b0; cnt <= 0; bitpos <= 0; sh <= 8'h00;
    end else if (!busy) begin
      if (start) begin
        busy <= 1'b1;
        sh   <= data;
        bitpos <= 0;
        cnt  <= 0;
        tx   <= 1'b0; // start bit
      end
    end else begin
      if (cnt == DIV-1) begin
        cnt <= 0;
        bitpos <= bitpos + 1'b1;
        case (bitpos)
          4'd0:   tx <= sh[0];
          4'd1:   tx <= sh[1];
          4'd2:   tx <= sh[2];
          4'd3:   tx <= sh[3];
          4'd4:   tx <= sh[4];
          4'd5:   tx <= sh[5];
          4'd6:   tx <= sh[6];
          4'd7:   tx <= sh[7];
          4'd8:   tx <= 1'b1; // stop bit
          default: begin
            tx <= 1'b1; busy <= 1'b0; // done
          end
        endcase
      end else begin
        cnt <= cnt + 1'b1;
      end
    end
  end
endmodule