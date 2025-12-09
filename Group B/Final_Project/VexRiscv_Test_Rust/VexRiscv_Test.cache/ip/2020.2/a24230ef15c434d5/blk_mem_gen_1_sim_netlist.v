// Copyright 1986-2020 Xilinx, Inc. All Rights Reserved.
// --------------------------------------------------------------------------------
// Tool Version: Vivado v.2020.2 (win64) Build 3064766 Wed Nov 18 09:12:45 MST 2020
// Date        : Tue Dec  2 13:48:41 2025
// Host        : MSI running 64-bit major release  (build 9200)
// Command     : write_verilog -force -mode funcsim -rename_top decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix -prefix
//               decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix_ blk_mem_gen_1_sim_netlist.v
// Design      : blk_mem_gen_1
// Purpose     : This verilog netlist is a functional simulation representation of the design and should not be modified
//               or synthesized. This netlist cannot be used for SDF annotated simulation.
// Device      : xc7a100tcsg324-1
// --------------------------------------------------------------------------------
`timescale 1 ps / 1 ps

(* CHECK_LICENSE_TYPE = "blk_mem_gen_1,blk_mem_gen_v8_4_4,{}" *) (* downgradeipidentifiedwarnings = "yes" *) (* x_core_info = "blk_mem_gen_v8_4_4,Vivado 2020.2" *) 
(* NotValidForBitStream *)
module decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix
   (clka,
    ena,
    wea,
    addra,
    dina,
    douta);
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA CLK" *) (* x_interface_parameter = "XIL_INTERFACENAME BRAM_PORTA, MEM_SIZE 8192, MEM_WIDTH 32, MEM_ECC NONE, MASTER_TYPE OTHER, READ_LATENCY 1" *) input clka;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA EN" *) input ena;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA WE" *) input [0:0]wea;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA ADDR" *) input [3:0]addra;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DIN" *) input [31:0]dina;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DOUT" *) output [31:0]douta;

  wire [3:0]addra;
  wire clka;
  wire [31:0]dina;
  wire [31:0]douta;
  wire ena;
  wire [0:0]wea;
  wire NLW_U0_dbiterr_UNCONNECTED;
  wire NLW_U0_rsta_busy_UNCONNECTED;
  wire NLW_U0_rstb_busy_UNCONNECTED;
  wire NLW_U0_s_axi_arready_UNCONNECTED;
  wire NLW_U0_s_axi_awready_UNCONNECTED;
  wire NLW_U0_s_axi_bvalid_UNCONNECTED;
  wire NLW_U0_s_axi_dbiterr_UNCONNECTED;
  wire NLW_U0_s_axi_rlast_UNCONNECTED;
  wire NLW_U0_s_axi_rvalid_UNCONNECTED;
  wire NLW_U0_s_axi_sbiterr_UNCONNECTED;
  wire NLW_U0_s_axi_wready_UNCONNECTED;
  wire NLW_U0_sbiterr_UNCONNECTED;
  wire [31:0]NLW_U0_doutb_UNCONNECTED;
  wire [3:0]NLW_U0_rdaddrecc_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_bid_UNCONNECTED;
  wire [1:0]NLW_U0_s_axi_bresp_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_rdaddrecc_UNCONNECTED;
  wire [31:0]NLW_U0_s_axi_rdata_UNCONNECTED;
  wire [3:0]NLW_U0_s_axi_rid_UNCONNECTED;
  wire [1:0]NLW_U0_s_axi_rresp_UNCONNECTED;

  (* C_ADDRA_WIDTH = "4" *) 
  (* C_ADDRB_WIDTH = "4" *) 
  (* C_ALGORITHM = "1" *) 
  (* C_AXI_ID_WIDTH = "4" *) 
  (* C_AXI_SLAVE_TYPE = "0" *) 
  (* C_AXI_TYPE = "1" *) 
  (* C_BYTE_SIZE = "9" *) 
  (* C_COMMON_CLK = "0" *) 
  (* C_COUNT_18K_BRAM = "1" *) 
  (* C_COUNT_36K_BRAM = "0" *) 
  (* C_CTRL_ECC_ALGO = "NONE" *) 
  (* C_DEFAULT_DATA = "0" *) 
  (* C_DISABLE_WARN_BHV_COLL = "0" *) 
  (* C_DISABLE_WARN_BHV_RANGE = "0" *) 
  (* C_ELABORATION_DIR = "./" *) 
  (* C_ENABLE_32BIT_ADDRESS = "0" *) 
  (* C_EN_DEEPSLEEP_PIN = "0" *) 
  (* C_EN_ECC_PIPE = "0" *) 
  (* C_EN_RDADDRA_CHG = "0" *) 
  (* C_EN_RDADDRB_CHG = "0" *) 
  (* C_EN_SAFETY_CKT = "0" *) 
  (* C_EN_SHUTDOWN_PIN = "0" *) 
  (* C_EN_SLEEP_PIN = "0" *) 
  (* C_EST_POWER_SUMMARY = "Estimated Power for IP     :     3.53845 mW" *) 
  (* C_FAMILY = "artix7" *) 
  (* C_HAS_AXI_ID = "0" *) 
  (* C_HAS_ENA = "1" *) 
  (* C_HAS_ENB = "0" *) 
  (* C_HAS_INJECTERR = "0" *) 
  (* C_HAS_MEM_OUTPUT_REGS_A = "1" *) 
  (* C_HAS_MEM_OUTPUT_REGS_B = "0" *) 
  (* C_HAS_MUX_OUTPUT_REGS_A = "0" *) 
  (* C_HAS_MUX_OUTPUT_REGS_B = "0" *) 
  (* C_HAS_REGCEA = "0" *) 
  (* C_HAS_REGCEB = "0" *) 
  (* C_HAS_RSTA = "0" *) 
  (* C_HAS_RSTB = "0" *) 
  (* C_HAS_SOFTECC_INPUT_REGS_A = "0" *) 
  (* C_HAS_SOFTECC_OUTPUT_REGS_B = "0" *) 
  (* C_INITA_VAL = "0" *) 
  (* C_INITB_VAL = "0" *) 
  (* C_INIT_FILE = "blk_mem_gen_1.mem" *) 
  (* C_INIT_FILE_NAME = "blk_mem_gen_1.mif" *) 
  (* C_INTERFACE_TYPE = "0" *) 
  (* C_LOAD_INIT_FILE = "1" *) 
  (* C_MEM_TYPE = "0" *) 
  (* C_MUX_PIPELINE_STAGES = "0" *) 
  (* C_PRIM_TYPE = "1" *) 
  (* C_READ_DEPTH_A = "16" *) 
  (* C_READ_DEPTH_B = "16" *) 
  (* C_READ_LATENCY_A = "1" *) 
  (* C_READ_LATENCY_B = "1" *) 
  (* C_READ_WIDTH_A = "32" *) 
  (* C_READ_WIDTH_B = "32" *) 
  (* C_RSTRAM_A = "0" *) 
  (* C_RSTRAM_B = "0" *) 
  (* C_RST_PRIORITY_A = "CE" *) 
  (* C_RST_PRIORITY_B = "CE" *) 
  (* C_SIM_COLLISION_CHECK = "ALL" *) 
  (* C_USE_BRAM_BLOCK = "0" *) 
  (* C_USE_BYTE_WEA = "0" *) 
  (* C_USE_BYTE_WEB = "0" *) 
  (* C_USE_DEFAULT_DATA = "0" *) 
  (* C_USE_ECC = "0" *) 
  (* C_USE_SOFTECC = "0" *) 
  (* C_USE_URAM = "0" *) 
  (* C_WEA_WIDTH = "1" *) 
  (* C_WEB_WIDTH = "1" *) 
  (* C_WRITE_DEPTH_A = "16" *) 
  (* C_WRITE_DEPTH_B = "16" *) 
  (* C_WRITE_MODE_A = "WRITE_FIRST" *) 
  (* C_WRITE_MODE_B = "WRITE_FIRST" *) 
  (* C_WRITE_WIDTH_A = "32" *) 
  (* C_WRITE_WIDTH_B = "32" *) 
  (* C_XDEVICEFAMILY = "artix7" *) 
  (* downgradeipidentifiedwarnings = "yes" *) 
  (* is_du_within_envelope = "true" *) 
  decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix_blk_mem_gen_v8_4_4 U0
       (.addra(addra),
        .addrb({1'b0,1'b0,1'b0,1'b0}),
        .clka(clka),
        .clkb(1'b0),
        .dbiterr(NLW_U0_dbiterr_UNCONNECTED),
        .deepsleep(1'b0),
        .dina(dina),
        .dinb({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .douta(douta),
        .doutb(NLW_U0_doutb_UNCONNECTED[31:0]),
        .eccpipece(1'b0),
        .ena(ena),
        .enb(1'b0),
        .injectdbiterr(1'b0),
        .injectsbiterr(1'b0),
        .rdaddrecc(NLW_U0_rdaddrecc_UNCONNECTED[3:0]),
        .regcea(1'b0),
        .regceb(1'b0),
        .rsta(1'b0),
        .rsta_busy(NLW_U0_rsta_busy_UNCONNECTED),
        .rstb(1'b0),
        .rstb_busy(NLW_U0_rstb_busy_UNCONNECTED),
        .s_aclk(1'b0),
        .s_aresetn(1'b0),
        .s_axi_araddr({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arburst({1'b0,1'b0}),
        .s_axi_arid({1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arlen({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_arready(NLW_U0_s_axi_arready_UNCONNECTED),
        .s_axi_arsize({1'b0,1'b0,1'b0}),
        .s_axi_arvalid(1'b0),
        .s_axi_awaddr({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awburst({1'b0,1'b0}),
        .s_axi_awid({1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awlen({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_awready(NLW_U0_s_axi_awready_UNCONNECTED),
        .s_axi_awsize({1'b0,1'b0,1'b0}),
        .s_axi_awvalid(1'b0),
        .s_axi_bid(NLW_U0_s_axi_bid_UNCONNECTED[3:0]),
        .s_axi_bready(1'b0),
        .s_axi_bresp(NLW_U0_s_axi_bresp_UNCONNECTED[1:0]),
        .s_axi_bvalid(NLW_U0_s_axi_bvalid_UNCONNECTED),
        .s_axi_dbiterr(NLW_U0_s_axi_dbiterr_UNCONNECTED),
        .s_axi_injectdbiterr(1'b0),
        .s_axi_injectsbiterr(1'b0),
        .s_axi_rdaddrecc(NLW_U0_s_axi_rdaddrecc_UNCONNECTED[3:0]),
        .s_axi_rdata(NLW_U0_s_axi_rdata_UNCONNECTED[31:0]),
        .s_axi_rid(NLW_U0_s_axi_rid_UNCONNECTED[3:0]),
        .s_axi_rlast(NLW_U0_s_axi_rlast_UNCONNECTED),
        .s_axi_rready(1'b0),
        .s_axi_rresp(NLW_U0_s_axi_rresp_UNCONNECTED[1:0]),
        .s_axi_rvalid(NLW_U0_s_axi_rvalid_UNCONNECTED),
        .s_axi_sbiterr(NLW_U0_s_axi_sbiterr_UNCONNECTED),
        .s_axi_wdata({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
        .s_axi_wlast(1'b0),
        .s_axi_wready(NLW_U0_s_axi_wready_UNCONNECTED),
        .s_axi_wstrb(1'b0),
        .s_axi_wvalid(1'b0),
        .sbiterr(NLW_U0_sbiterr_UNCONNECTED),
        .shutdown(1'b0),
        .sleep(1'b0),
        .wea(wea),
        .web(1'b0));
endmodule
`pragma protect begin_protected
`pragma protect version = 1
`pragma protect encrypt_agent = "XILINX"
`pragma protect encrypt_agent_info = "Xilinx Encryption Tool 2020.2"
`pragma protect key_keyowner="Cadence Design Systems.", key_keyname="cds_rsa_key", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=64)
`pragma protect key_block
QGLtnqZzRetDH6gCWT4Js6wuLlZfrNx/VJp3sfR2NF+cxypO5AxN0oDKLJJtmdrtE/ueNDg+Qf7Z
TqBNRojORA==

`pragma protect key_keyowner="Synopsys", key_keyname="SNPS-VCS-RSA-2", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=128)
`pragma protect key_block
B6Ger3hRvfjHkaJ+W8639Kl3TzC9TogLuklOXEiMNdc4Im+DjEUzxb3DKlzu0VW3zxZqjJ3+wsW/
LnRmPCESi5Y9eRJaLFXg79EMfoj4X+nTdHAP6yCfltBADKegZ12gpnB/8ey5yn2KA74LUtPC7jna
iyjqSfsWLGnz6UdXzwk=

`pragma protect key_keyowner="Aldec", key_keyname="ALDEC15_001", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
BX+DxgMPRyZbYojCUR9Sk8Lq+3ZigBz4yMFHQkmurfdfDzyTPJCE827eGiPyTenK1QPVhEtf9g06
0BFXq/0COPuU1BWJwdkz1c4dE6/exDwhvEh+hPx3vRY6z8fDEf6aGVIXrHDvrmddehe7yMSIpo+k
aXHR06EEdfHCFY4TggYwhcJVXjkE+ApsVuyfmEfPmYjo8hCWyQyBsUWIOY03q1+MvUjjsmTwgs9g
fh5MY9ToaLfoJxPKdCpsqrBX4LJ+VDGFlAqIcqHTE2jCmPiToZAFXB7fzf1wDjFCBlJyFVDBGi0i
m+CouLSb7X1mvVhdDZgNrZDJMV688Bu3o54vew==

`pragma protect key_keyowner="ATRENTA", key_keyname="ATR-SG-2015-RSA-3", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
DaIU/Ddc8USbZ2mURzujJDWDH1JbHl5tFVOOQ2aVaUPIA71yyE38OXVLEtF8rNmujYH30nEeQ+FV
LVJ16aaHw+iiuaqorTM3K5KLohVlN+WlcEtSXHuPNHjw8ddqtzpaX7pH1zqZH+YmfCL5oaNLqDH4
rkBnUl0/Gm/hzSwKjYhXGQFYQ+gGP99OjXakzrAqZzp/Iq4gt+Z5902/JV9thd/isHQImJ0QyK8M
EKM579iPAfXGes2mbiNYHcvDmSPYmW1zlhOE++N1EKeea7j/msnKeyhlC+hGE4Xfn4TVvqgQexCT
rp/wS/MosY6WH1aKFQlFH2hEppA7KXUaQlvG+w==

`pragma protect key_keyowner="Mentor Graphics Corporation", key_keyname="MGC-VELOCE-RSA", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=128)
`pragma protect key_block
XmWoAt4X8hrCJ5yTyug4ajJW5UhfkLNibzjihWzZ4Cr9hQSvWZoTc8rjGsLPbz6Le+/9iI5KxecS
eR0wiAO+G2IkwhZgVBeZdKoFnlnTVAyLjk9wMAFXNyJZM6b1NDbfXlPcUsC6JePvPlwwdWknkSsC
r3KvgkWAS+O3xvRmaNw=

`pragma protect key_keyowner="Mentor Graphics Corporation", key_keyname="MGC-VERIF-SIM-RSA-2", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
Hw3Y+rShKrXiUViyNU1/O2qv6TgheLHBnFMj1i9MUGrHYqh9pLfLYUgWR7S2vj4jv4S+Ks0BpP4p
dKEqVAFmTCfQNEUHaVcFPkOHgig6L4mhLY6HUUKJoRgiQepgLi/W3V+ZZPQSQFkB3CU4MsJzhXvR
yLcpDriZy8cnAHD87Zi5DrNGBzj3kigJeM0du6lCQbxtF5aEdoaNP+YTnIFtcqYhoYnswQlYt0sV
HKgFA8VzqzL5WYnpH7+1IKmFkJBHkyqHCa9wPK0qCKnxkuDj70YzPVqQ+cocdKU+/gNdpCOdZlci
F2HTxrgfrXndJru3TiDqu4UavqAe0MNuFp3t0w==

`pragma protect key_keyowner="Real Intent", key_keyname="RI-RSA-KEY-1", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
XPVggoWL6aXz+MpODTOZhEUQDa0vfEnUDaYeEHXm2vGyqKJujN2c/FFAFBeBYdJATLsIsQ+BqoPc
pBbcFYXDBfOtFIW2dH6Y1OoD65KyJ/hAq8coa21kFgq4hFat5vzZ2iIfkCpTUr4vDZO7Xne8cZO9
WsHffoTCt5rS59wWm2b8I5R8Eh2TUbQg3RCyrcnD66cvcEnlXe1CNMQ4/loVJpA4IBinBf820Wjc
vw2fZbGI0jXC+ACSHOviH63Xwmn+aRV5Ppkup7IYoon/ieKapRQeASu3TTY37xSBXiInSdtMTzJ6
+4GfO4eSHVriCk/sWbuTBzfRzoSShrnHjzz5LA==

`pragma protect key_keyowner="Xilinx", key_keyname="xilinxt_2020_08", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
L78XuiswVcgO2gtebzL7SA9BC/jJGAM0v6S9pzmyqL+QYzRneiYeGyDmsW33jEVVSTuNjTXkBLY7
yTOKQruatwe4V0OLi6174saSAmPgerSV1GyLP7KhmusLV/N61avC9TPam+tekhKeE0tds4EnJ3et
4JdLh+SE4Z4pcuqCjB5MFneIYKKWDx7siU6oesAQtoSJOesfMchX63MhOjOHFP/ch+1gHv3T45hg
IGF7V7TrdREVE4f9631tlVJ1o2Dypsmo/76Itz5WCGlTMjAnWXN8IXxKN+PZ3dyt1wjrZm2P/td+
xiGszFnSLrRvw/HferwtSmRx8q0fiHZ88roGTw==

`pragma protect key_keyowner="Metrics Technologies Inc.", key_keyname="DSim", key_method="rsa"
`pragma protect encoding = (enctype="BASE64", line_length=76, bytes=256)
`pragma protect key_block
kDX5kq2QEe25429T6vQqBCFvV1McKTJRYfK99ymVNK2GGvGLXSzgwJHwB2fj9rM0wme3zYYY0vQR
x+9F4L7KLlOVY6qY3LB59uDzyXBI3mMZaS905HXHJkdZHWtQWpfHhl27LqL+8FSluaD6F+KFfYOV
CwIOVuCIp/XjxFXpNBik7YiPt4kHOlDA97IXNLnYUn/g1csGqeNWce4UTne50ggWvLYGbTFGmTjT
N67TpUiGRVRCSv8Tax72GWFIMFZk3Tlp68ZUSQEybZMWX1U9XdMdtxfvNGhf8mi5jQJ2SupSzKu4
T/+53IN9T8aLePAiGBKKG1ZBj4y1ZyYA7XYvjw==

`pragma protect data_method = "AES128-CBC"
`pragma protect encoding = (enctype = "BASE64", line_length = 76, bytes = 19488)
`pragma protect data_block
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
`pragma protect end_protected
`ifndef GLBL
`define GLBL
`timescale  1 ps / 1 ps

module glbl ();

    parameter ROC_WIDTH = 100000;
    parameter TOC_WIDTH = 0;
    parameter GRES_WIDTH = 10000;
    parameter GRES_START = 10000;

//--------   STARTUP Globals --------------
    wire GSR;
    wire GTS;
    wire GWE;
    wire PRLD;
    wire GRESTORE;
    tri1 p_up_tmp;
    tri (weak1, strong0) PLL_LOCKG = p_up_tmp;

    wire PROGB_GLBL;
    wire CCLKO_GLBL;
    wire FCSBO_GLBL;
    wire [3:0] DO_GLBL;
    wire [3:0] DI_GLBL;
   
    reg GSR_int;
    reg GTS_int;
    reg PRLD_int;
    reg GRESTORE_int;

//--------   JTAG Globals --------------
    wire JTAG_TDO_GLBL;
    wire JTAG_TCK_GLBL;
    wire JTAG_TDI_GLBL;
    wire JTAG_TMS_GLBL;
    wire JTAG_TRST_GLBL;

    reg JTAG_CAPTURE_GLBL;
    reg JTAG_RESET_GLBL;
    reg JTAG_SHIFT_GLBL;
    reg JTAG_UPDATE_GLBL;
    reg JTAG_RUNTEST_GLBL;

    reg JTAG_SEL1_GLBL = 0;
    reg JTAG_SEL2_GLBL = 0 ;
    reg JTAG_SEL3_GLBL = 0;
    reg JTAG_SEL4_GLBL = 0;

    reg JTAG_USER_TDO1_GLBL = 1'bz;
    reg JTAG_USER_TDO2_GLBL = 1'bz;
    reg JTAG_USER_TDO3_GLBL = 1'bz;
    reg JTAG_USER_TDO4_GLBL = 1'bz;

    assign (strong1, weak0) GSR = GSR_int;
    assign (strong1, weak0) GTS = GTS_int;
    assign (weak1, weak0) PRLD = PRLD_int;
    assign (strong1, weak0) GRESTORE = GRESTORE_int;

    initial begin
	GSR_int = 1'b1;
	PRLD_int = 1'b1;
	#(ROC_WIDTH)
	GSR_int = 1'b0;
	PRLD_int = 1'b0;
    end

    initial begin
	GTS_int = 1'b1;
	#(TOC_WIDTH)
	GTS_int = 1'b0;
    end

    initial begin 
	GRESTORE_int = 1'b0;
	#(GRES_START);
	GRESTORE_int = 1'b1;
	#(GRES_WIDTH);
	GRESTORE_int = 1'b0;
    end

endmodule
`endif
