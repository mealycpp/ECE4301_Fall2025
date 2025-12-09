// Copyright 1986-2020 Xilinx, Inc. All Rights Reserved.
// --------------------------------------------------------------------------------
// Tool Version: Vivado v.2020.2 (win64) Build 3064766 Wed Nov 18 09:12:45 MST 2020
// Date        : Tue Dec  2 13:47:38 2025
// Host        : MSI running 64-bit major release  (build 9200)
// Command     : write_verilog -force -mode funcsim -rename_top decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix -prefix
//               decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix_ blk_mem_gen_0_sim_netlist.v
// Design      : blk_mem_gen_0
// Purpose     : This verilog netlist is a functional simulation representation of the design and should not be modified
//               or synthesized. This netlist cannot be used for SDF annotated simulation.
// Device      : xc7a100tcsg324-1
// --------------------------------------------------------------------------------
`timescale 1 ps / 1 ps

(* CHECK_LICENSE_TYPE = "blk_mem_gen_0,blk_mem_gen_v8_4_4,{}" *) (* downgradeipidentifiedwarnings = "yes" *) (* x_core_info = "blk_mem_gen_v8_4_4,Vivado 2020.2" *) 
(* NotValidForBitStream *)
module decalper_eb_ot_sdeen_pot_pi_dehcac_xnilix
   (clka,
    ena,
    addra,
    douta);
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA CLK" *) (* x_interface_parameter = "XIL_INTERFACENAME BRAM_PORTA, MEM_SIZE 8192, MEM_WIDTH 32, MEM_ECC NONE, MASTER_TYPE OTHER, READ_LATENCY 1" *) input clka;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA EN" *) input ena;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA ADDR" *) input [3:0]addra;
  (* x_interface_info = "xilinx.com:interface:bram:1.0 BRAM_PORTA DOUT" *) output [31:0]douta;

  wire [3:0]addra;
  wire clka;
  wire [31:0]douta;
  wire ena;
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
  (* C_EST_POWER_SUMMARY = "Estimated Power for IP     :     3.375199 mW" *) 
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
  (* C_INIT_FILE = "blk_mem_gen_0.mem" *) 
  (* C_INIT_FILE_NAME = "blk_mem_gen_0.mif" *) 
  (* C_INTERFACE_TYPE = "0" *) 
  (* C_LOAD_INIT_FILE = "1" *) 
  (* C_MEM_TYPE = "3" *) 
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
        .dina({1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0,1'b0}),
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
        .wea(1'b0),
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
`pragma protect encoding = (enctype = "BASE64", line_length = 76, bytes = 18928)
`pragma protect data_block
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
6Dz3eg==
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
