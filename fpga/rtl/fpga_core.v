/*

Copyright (c) 2020 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

// Language: Verilog 2001

`resetall
`timescale 1ns / 1ps
`default_nettype none

/*
 * FPGA1 core logic - UART RX → ASCON Encrypt → Ethernet TX
 *
 * Data path:
 *   PC1 → UART RX → async FIFO (125→62.5MHz) → ASCON encrypt → async FIFO (62.5→125MHz) → UDP TX → FPGA2
 *
 * Ethernet RX is only used for ARP responses (no data path).
 * UDP RX payload is drained (accepted and discarded) to prevent UDP stack from stalling.
 */
module fpga_core #
(
    parameter TARGET = "GENERIC"
)
(
    input  wire       clk,       // 125 MHz
    input  wire       clk90,     // 125 MHz + 90 deg
    input  wire       clk_slow,  // 62.5 MHz
    input  wire       rst,       // 125 MHz domain reset
    input  wire       rst_slow,  // 62.5 MHz domain reset

    input  wire [3:0]  btn,
    input  wire [17:0] sw,
    output wire [8:0]  ledg,
    output wire [17:0] ledr,
    output wire [6:0]  hex0,
    output wire [6:0]  hex1,
    output wire [6:0]  hex2,
    output wire [6:0]  hex3,
    output wire [6:0]  hex4,
    output wire [6:0]  hex5,
    output wire [6:0]  hex6,
    output wire [6:0]  hex7,
    output wire [35:0] gpio,

    input  wire       phy0_rx_clk,
    input  wire [3:0] phy0_rxd,
    input  wire       phy0_rx_ctl,
    output wire       phy0_tx_clk,
    output wire [3:0] phy0_txd,
    output wire       phy0_tx_ctl,
    output wire       phy0_reset_n,
    input  wire       phy0_int_n,

    input  wire       phy1_rx_clk,
    input  wire [3:0] phy1_rxd,
    input  wire       phy1_rx_ctl,
    output wire       phy1_tx_clk,
    output wire [3:0] phy1_txd,
    output wire       phy1_tx_ctl,
    output wire       phy1_reset_n,
    input  wire       phy1_int_n,

    /*
     * UART interface (directly exposed from fpga.v)
     */
    input  wire       uart_rxd    // RS-232 RX pin (from PC1 via USB-RS232 adapter)
);

// ================================================================
// FPGA2 address configuration (hardcoded destination)
// ================================================================
localparam [31:0] FPGA2_IP   = {8'd192, 8'd168, 8'd1, 8'd129};
localparam [15:0] UDP_PORT   = 16'd1234;

// ================================================================
// UART parameters
// ================================================================
// 125 MHz / (115200 baud * 8) = ~136
localparam UART_PRESCALE = 125000000 / (115200 * 8);

// ================================================================
// Internal wires
// ================================================================

// AXI between MAC and Ethernet modules
wire [7:0] rx_axis_tdata;
wire rx_axis_tvalid;
wire rx_axis_tready;
wire rx_axis_tlast;
wire rx_axis_tuser;

wire [7:0] tx_axis_tdata;
wire tx_axis_tvalid;
wire tx_axis_tready;
wire tx_axis_tlast;
wire tx_axis_tuser;

// Ethernet frame
wire rx_eth_hdr_ready;
wire rx_eth_hdr_valid;
wire [47:0] rx_eth_dest_mac;
wire [47:0] rx_eth_src_mac;
wire [15:0] rx_eth_type;
wire [7:0] rx_eth_payload_axis_tdata;
wire rx_eth_payload_axis_tvalid;
wire rx_eth_payload_axis_tready;
wire rx_eth_payload_axis_tlast;
wire rx_eth_payload_axis_tuser;

wire tx_eth_hdr_ready;
wire tx_eth_hdr_valid;
wire [47:0] tx_eth_dest_mac;
wire [47:0] tx_eth_src_mac;
wire [15:0] tx_eth_type;
wire [7:0] tx_eth_payload_axis_tdata;
wire tx_eth_payload_axis_tvalid;
wire tx_eth_payload_axis_tready;
wire tx_eth_payload_axis_tlast;
wire tx_eth_payload_axis_tuser;

// IP frame
wire rx_ip_hdr_valid;
wire rx_ip_hdr_ready;
wire [47:0] rx_ip_eth_dest_mac;
wire [47:0] rx_ip_eth_src_mac;
wire [15:0] rx_ip_eth_type;
wire [3:0] rx_ip_version;
wire [3:0] rx_ip_ihl;
wire [5:0] rx_ip_dscp;
wire [1:0] rx_ip_ecn;
wire [15:0] rx_ip_length;
wire [15:0] rx_ip_identification;
wire [2:0] rx_ip_flags;
wire [12:0] rx_ip_fragment_offset;
wire [7:0] rx_ip_ttl;
wire [7:0] rx_ip_protocol;
wire [15:0] rx_ip_header_checksum;
wire [31:0] rx_ip_source_ip;
wire [31:0] rx_ip_dest_ip;
wire [7:0] rx_ip_payload_axis_tdata;
wire rx_ip_payload_axis_tvalid;
wire rx_ip_payload_axis_tready;
wire rx_ip_payload_axis_tlast;
wire rx_ip_payload_axis_tuser;

wire tx_ip_hdr_valid;
wire tx_ip_hdr_ready;
wire [5:0] tx_ip_dscp;
wire [1:0] tx_ip_ecn;
wire [15:0] tx_ip_length;
wire [7:0] tx_ip_ttl;
wire [7:0] tx_ip_protocol;
wire [31:0] tx_ip_source_ip;
wire [31:0] tx_ip_dest_ip;
wire [7:0] tx_ip_payload_axis_tdata;
wire tx_ip_payload_axis_tvalid;
wire tx_ip_payload_axis_tready;
wire tx_ip_payload_axis_tlast;
wire tx_ip_payload_axis_tuser;

// UDP frame
wire rx_udp_hdr_valid;
wire rx_udp_hdr_ready;
wire [47:0] rx_udp_eth_dest_mac;
wire [47:0] rx_udp_eth_src_mac;
wire [15:0] rx_udp_eth_type;
wire [3:0] rx_udp_ip_version;
wire [3:0] rx_udp_ip_ihl;
wire [5:0] rx_udp_ip_dscp;
wire [1:0] rx_udp_ip_ecn;
wire [15:0] rx_udp_ip_length;
wire [15:0] rx_udp_ip_identification;
wire [2:0] rx_udp_ip_flags;
wire [12:0] rx_udp_ip_fragment_offset;
wire [7:0] rx_udp_ip_ttl;
wire [7:0] rx_udp_ip_protocol;
wire [15:0] rx_udp_ip_header_checksum;
wire [31:0] rx_udp_ip_source_ip;
wire [31:0] rx_udp_ip_dest_ip;
wire [15:0] rx_udp_source_port;
wire [15:0] rx_udp_dest_port;
wire [15:0] rx_udp_length;
wire [15:0] rx_udp_checksum;
wire [7:0] rx_udp_payload_axis_tdata;
wire rx_udp_payload_axis_tvalid;
wire rx_udp_payload_axis_tready;
wire rx_udp_payload_axis_tlast;
wire rx_udp_payload_axis_tuser;

wire tx_udp_hdr_valid;
wire tx_udp_hdr_ready;
wire [5:0] tx_udp_ip_dscp;
wire [1:0] tx_udp_ip_ecn;
wire [7:0] tx_udp_ip_ttl;
wire [31:0] tx_udp_ip_source_ip;
wire [31:0] tx_udp_ip_dest_ip;
wire [15:0] tx_udp_source_port;
wire [15:0] tx_udp_dest_port;
wire [15:0] tx_udp_length;
wire [15:0] tx_udp_checksum;
wire [7:0] tx_udp_payload_axis_tdata;
wire tx_udp_payload_axis_tvalid;
wire tx_udp_payload_axis_tready;
wire tx_udp_payload_axis_tlast;
wire tx_udp_payload_axis_tuser;

// UART RX output (AXI-Stream, 125MHz domain, no tlast)
wire [7:0] uart_rx_tdata;
wire       uart_rx_tvalid;
wire       uart_rx_tready;

// UART RX with tlast added (125MHz domain)
wire [7:0] uart_pkt_tdata;
wire       uart_pkt_tvalid;
wire       uart_pkt_tready;
wire       uart_pkt_tlast;

// Async FIFO RX output (62.5MHz domain → ASCON input)
wire [7:0] slow_rx_tdata;
wire slow_rx_tvalid;
wire slow_rx_tready;
wire slow_rx_tlast;

// ASCON wrapper output (62.5MHz domain)
wire [7:0] slow_tx_tdata;
wire slow_tx_tvalid;
wire slow_tx_tready;
wire slow_tx_tlast;

// Async FIFO TX output (125MHz domain → UDP TX)
wire [7:0] ascon_out_tdata;
wire ascon_out_tvalid;
wire ascon_out_tready;
wire ascon_out_tlast;

// Configuration
wire [47:0] local_mac   = 48'h02_00_00_00_00_00;
wire [31:0] local_ip    = {8'd192, 8'd168, 8'd1,   8'd128};
wire [31:0] gateway_ip  = {8'd192, 8'd168, 8'd1,   8'd1};
wire [31:0] subnet_mask = {8'd255, 8'd255, 8'd255, 8'd0};

// ================================================================
// IP ports not used — assign defaults
// ================================================================
assign rx_ip_hdr_ready = 1;
assign rx_ip_payload_axis_tready = 1;
assign tx_ip_hdr_valid = 0;
assign tx_ip_dscp = 0;
assign tx_ip_ecn = 0;
assign tx_ip_length = 0;
assign tx_ip_ttl = 0;
assign tx_ip_protocol = 0;
assign tx_ip_source_ip = 0;
assign tx_ip_dest_ip = 0;
assign tx_ip_payload_axis_tdata = 0;
assign tx_ip_payload_axis_tvalid = 0;
assign tx_ip_payload_axis_tlast = 0;
assign tx_ip_payload_axis_tuser = 0;

// ================================================================
// UDP RX — drain all incoming payload (we don't use Ethernet RX for data)
// ARP still works because udp_complete handles ARP at Ethernet frame level,
// independent of the UDP payload path.
// ================================================================
assign rx_udp_hdr_ready = 1;                       // always accept headers
assign rx_udp_payload_axis_tready = 1;             // always drain payload

// ================================================================
// TX UDP Header — hardcoded destination (FPGA2)
// No header latch needed since we don't use RX headers.
// Header is sent when ASCON output is ready.
// ================================================================
reg hdr_pending = 0;
reg hdr_sent = 0;

always @(posedge clk) begin
    if (rst) begin
        hdr_pending <= 0;
        hdr_sent    <= 0;
    end else begin
        // When ASCON output becomes valid, start sending header
        if (ascon_out_tvalid && !hdr_pending && !hdr_sent) begin
            hdr_pending <= 1;
        end

        // Header accepted by UDP stack
        if (hdr_pending && tx_udp_hdr_ready) begin
            hdr_pending <= 0;
            hdr_sent    <= 1;
        end

        // Packet finished (tlast), ready for next packet
        if (hdr_sent && ascon_out_tvalid && ascon_out_tready && ascon_out_tlast) begin
            hdr_sent <= 0;
        end
    end
end

assign tx_udp_hdr_valid    = hdr_pending;
assign tx_udp_ip_dscp      = 0;
assign tx_udp_ip_ecn       = 0;
assign tx_udp_ip_ttl       = 64;
assign tx_udp_ip_source_ip = local_ip;             // 192.168.1.128
assign tx_udp_ip_dest_ip   = FPGA2_IP;             // 192.168.1.129 (hardcoded)
assign tx_udp_source_port  = UDP_PORT;              // 1234
assign tx_udp_dest_port    = UDP_PORT;              // 1234
assign tx_udp_checksum     = 0;

// ================================================================
// TX UDP Length — we don't know payload size in advance from UART.
// Set to 0, udp_complete will calculate it from tlast.
// NOTE: If udp_complete doesn't support length=0, we need to
// track byte count. For now try 0 (auto-calculate).
// ================================================================
assign tx_udp_length = 0;

// ================================================================
// TX UDP Payload — ASCON output → UDP TX (gated by hdr_sent)
// Payload only flows after header has been accepted by UDP stack.
// ================================================================
assign tx_udp_payload_axis_tdata  = ascon_out_tdata;
assign tx_udp_payload_axis_tvalid = hdr_sent ? ascon_out_tvalid : 1'b0;
assign ascon_out_tready           = hdr_sent ? tx_udp_payload_axis_tready : 1'b0;
assign tx_udp_payload_axis_tlast  = ascon_out_tlast;
assign tx_udp_payload_axis_tuser  = 1'b0;

// ================================================================
// UART RX Module (alexforencich/verilog-uart)
// Receives bytes from PC1 via RS-232.
// Output: AXI-Stream 8-bit, no tlast (UART is continuous byte stream).
// ================================================================
uart_rx #(
    .DATA_WIDTH(8)
)
uart_rx_inst (
    .clk(clk),
    .rst(rst),

    // AXI-Stream output
    .m_axis_tdata(uart_rx_tdata),
    .m_axis_tvalid(uart_rx_tvalid),
    .m_axis_tready(uart_rx_tready),

    // UART interface
    .rxd(uart_rxd),

    // Status (unused)
    .busy(),
    .overrun_error(),
    .frame_error(),

    // Baud rate: prescale = clk / (baud * 8)
    .prescale(UART_PRESCALE)
);

// ================================================================
// UART Packet Framer — adds tlast to UART byte stream
//
// UART has no packet boundaries. We use a timeout mechanism:
// If no new byte arrives within TIMEOUT clock cycles after the last byte,
// we consider the packet complete and assert tlast on the last byte.
//
// At 115200 baud, one byte takes ~87us = ~10,875 cycles @ 125MHz.
// Timeout of 50,000 cycles = ~0.4ms = about 4.5 byte periods.
// This gives PC enough time between bytes but catches end-of-message.
// ================================================================
// ================================================================
// UART Packet Framer — DÜZELTILMIS
// Byte'ı tutar, yeni byte gelirse öncekini tlast=0 ile gönderir,
// timeout olursa tlast=1 ile gönderir.
// ================================================================
localparam UART_TIMEOUT = 16'd50000;

reg [15:0] idle_counter = 0;
reg [7:0]  out_data = 0;
reg [7:0]  held_data = 0;
reg        held_valid = 0;
reg        can_output = 0;
reg        held_last = 0;

assign uart_pkt_tdata  = out_data;
assign uart_pkt_tvalid = can_output;
assign uart_pkt_tlast  = held_last;
assign uart_rx_tready  = !can_output;  // yeni byte kabul et, output meşgul değilse

always @(posedge clk) begin
    if (rst) begin
        idle_counter <= 0;
        held_data    <= 0;
        out_data     <= 0;
        held_valid   <= 0;
        can_output   <= 0;
        held_last    <= 0;
    end else begin
        // Çıkış tüketildi
        if (can_output && uart_pkt_tready) begin
            can_output <= 0;
            held_last  <= 0;
        end

        // Yeni byte geldi
        if (uart_rx_tvalid && uart_rx_tready) begin
            if (held_valid) begin
                // Önceki byte'ı çıkışa gönder (tlast=0)
                out_data   <= held_data;
                can_output <= 1;
                held_last  <= 0;
            end
            // Yeni byte'ı buffer'a al
            held_data    <= uart_rx_tdata;
            held_valid   <= 1;
            idle_counter <= 0;
        end else if (held_valid && !can_output) begin
            // Yeni byte yok, timeout say
            if (idle_counter < UART_TIMEOUT) begin
                idle_counter <= idle_counter + 1;
            end else begin
                // Timeout — son byte'ı tlast=1 ile gönder
                out_data     <= held_data;
                can_output   <= 1;
                held_last    <= 1;
                held_valid   <= 0;
                idle_counter <= 0;
            end
        end
    end
end

// ================================================================
// LED displays
// ================================================================
reg valid_last = 0;
reg [7:0] led_reg = 0;

always @(posedge clk) begin
    if (tx_udp_payload_axis_tvalid) begin
        if (!valid_last) begin
            led_reg <= tx_udp_payload_axis_tdata;
            valid_last <= 1'b1;
        end
        if (tx_udp_payload_axis_tlast) begin
            valid_last <= 1'b0;
        end
    end
    if (rst) begin
        led_reg <= 0;
    end
end

reg [31:0] dest_ip_reg = 0;

always @(posedge clk) begin
    if (tx_udp_hdr_valid && tx_udp_hdr_ready) begin
        dest_ip_reg <= tx_udp_ip_dest_ip;
    end
    if (rst) begin
        dest_ip_reg <= 0;
    end
end

hex_display #(.INVERT(1)) hex_display_0 (.in(dest_ip_reg[3:0]),   .enable(1), .out(hex0));
hex_display #(.INVERT(1)) hex_display_1 (.in(dest_ip_reg[7:4]),   .enable(1), .out(hex1));
hex_display #(.INVERT(1)) hex_display_2 (.in(dest_ip_reg[11:8]),  .enable(1), .out(hex2));
hex_display #(.INVERT(1)) hex_display_3 (.in(dest_ip_reg[15:12]), .enable(1), .out(hex3));
hex_display #(.INVERT(1)) hex_display_4 (.in(dest_ip_reg[19:16]), .enable(1), .out(hex4));
hex_display #(.INVERT(1)) hex_display_5 (.in(dest_ip_reg[23:20]), .enable(1), .out(hex5));
hex_display #(.INVERT(1)) hex_display_6 (.in(dest_ip_reg[27:24]), .enable(1), .out(hex6));
hex_display #(.INVERT(1)) hex_display_7 (.in(dest_ip_reg[31:28]), .enable(1), .out(hex7));

assign ledg = led_reg;
assign ledr = sw;
assign phy0_reset_n = ~rst;
assign phy1_reset_n = ~rst;
assign gpio = 0;

// ================================================================
// Ethernet MAC (125MHz) — handles both ARP and UDP frames
// ================================================================
eth_mac_1g_rgmii_fifo #(
    .TARGET(TARGET),
    .USE_CLK90("TRUE"),
    .ENABLE_PADDING(1),
    .MIN_FRAME_LENGTH(64),
    .TX_FIFO_DEPTH(4096),
    .TX_FRAME_FIFO(1),
    .RX_FIFO_DEPTH(4096),
    .RX_FRAME_FIFO(1)
)
eth_mac_inst (
    .gtx_clk(clk),
    .gtx_clk90(clk90),
    .gtx_rst(rst),
    .logic_clk(clk),
    .logic_rst(rst),
    .tx_axis_tdata(tx_axis_tdata),
    .tx_axis_tvalid(tx_axis_tvalid),
    .tx_axis_tready(tx_axis_tready),
    .tx_axis_tlast(tx_axis_tlast),
    .tx_axis_tuser(tx_axis_tuser),
    .rx_axis_tdata(rx_axis_tdata),
    .rx_axis_tvalid(rx_axis_tvalid),
    .rx_axis_tready(rx_axis_tready),
    .rx_axis_tlast(rx_axis_tlast),
    .rx_axis_tuser(rx_axis_tuser),
    .rgmii_rx_clk(phy0_rx_clk),
    .rgmii_rxd(phy0_rxd),
    .rgmii_rx_ctl(phy0_rx_ctl),
    .rgmii_tx_clk(phy0_tx_clk),
    .rgmii_txd(phy0_txd),
    .rgmii_tx_ctl(phy0_tx_ctl),
    .tx_fifo_overflow(),
    .tx_fifo_bad_frame(),
    .tx_fifo_good_frame(),
    .rx_error_bad_frame(),
    .rx_error_bad_fcs(),
    .rx_fifo_overflow(),
    .rx_fifo_bad_frame(),
    .rx_fifo_good_frame(),
    .speed(),
    .cfg_ifg(8'd12),
    .cfg_tx_enable(1'b1),
    .cfg_rx_enable(1'b1)
);

eth_axis_rx eth_axis_rx_inst (
    .clk(clk),
    .rst(rst),
    .s_axis_tdata(rx_axis_tdata),
    .s_axis_tvalid(rx_axis_tvalid),
    .s_axis_tready(rx_axis_tready),
    .s_axis_tlast(rx_axis_tlast),
    .s_axis_tuser(rx_axis_tuser),
    .m_eth_hdr_valid(rx_eth_hdr_valid),
    .m_eth_hdr_ready(rx_eth_hdr_ready),
    .m_eth_dest_mac(rx_eth_dest_mac),
    .m_eth_src_mac(rx_eth_src_mac),
    .m_eth_type(rx_eth_type),
    .m_eth_payload_axis_tdata(rx_eth_payload_axis_tdata),
    .m_eth_payload_axis_tvalid(rx_eth_payload_axis_tvalid),
    .m_eth_payload_axis_tready(rx_eth_payload_axis_tready),
    .m_eth_payload_axis_tlast(rx_eth_payload_axis_tlast),
    .m_eth_payload_axis_tuser(rx_eth_payload_axis_tuser),
    .busy(),
    .error_header_early_termination()
);

eth_axis_tx eth_axis_tx_inst (
    .clk(clk),
    .rst(rst),
    .s_eth_hdr_valid(tx_eth_hdr_valid),
    .s_eth_hdr_ready(tx_eth_hdr_ready),
    .s_eth_dest_mac(tx_eth_dest_mac),
    .s_eth_src_mac(tx_eth_src_mac),
    .s_eth_type(tx_eth_type),
    .s_eth_payload_axis_tdata(tx_eth_payload_axis_tdata),
    .s_eth_payload_axis_tvalid(tx_eth_payload_axis_tvalid),
    .s_eth_payload_axis_tready(tx_eth_payload_axis_tready),
    .s_eth_payload_axis_tlast(tx_eth_payload_axis_tlast),
    .s_eth_payload_axis_tuser(tx_eth_payload_axis_tuser),
    .m_axis_tdata(tx_axis_tdata),
    .m_axis_tvalid(tx_axis_tvalid),
    .m_axis_tready(tx_axis_tready),
    .m_axis_tlast(tx_axis_tlast),
    .m_axis_tuser(tx_axis_tuser),
    .busy()
);

udp_complete udp_complete_inst (
    .clk(clk),
    .rst(rst),
    // Ethernet frame input — needed for ARP
    .s_eth_hdr_valid(rx_eth_hdr_valid),
    .s_eth_hdr_ready(rx_eth_hdr_ready),
    .s_eth_dest_mac(rx_eth_dest_mac),
    .s_eth_src_mac(rx_eth_src_mac),
    .s_eth_type(rx_eth_type),
    .s_eth_payload_axis_tdata(rx_eth_payload_axis_tdata),
    .s_eth_payload_axis_tvalid(rx_eth_payload_axis_tvalid),
    .s_eth_payload_axis_tready(rx_eth_payload_axis_tready),
    .s_eth_payload_axis_tlast(rx_eth_payload_axis_tlast),
    .s_eth_payload_axis_tuser(rx_eth_payload_axis_tuser),
    // Ethernet frame output — needed for ARP replies and UDP TX
    .m_eth_hdr_valid(tx_eth_hdr_valid),
    .m_eth_hdr_ready(tx_eth_hdr_ready),
    .m_eth_dest_mac(tx_eth_dest_mac),
    .m_eth_src_mac(tx_eth_src_mac),
    .m_eth_type(tx_eth_type),
    .m_eth_payload_axis_tdata(tx_eth_payload_axis_tdata),
    .m_eth_payload_axis_tvalid(tx_eth_payload_axis_tvalid),
    .m_eth_payload_axis_tready(tx_eth_payload_axis_tready),
    .m_eth_payload_axis_tlast(tx_eth_payload_axis_tlast),
    .m_eth_payload_axis_tuser(tx_eth_payload_axis_tuser),
    // IP frame input — not used
    .s_ip_hdr_valid(tx_ip_hdr_valid),
    .s_ip_hdr_ready(tx_ip_hdr_ready),
    .s_ip_dscp(tx_ip_dscp),
    .s_ip_ecn(tx_ip_ecn),
    .s_ip_length(tx_ip_length),
    .s_ip_ttl(tx_ip_ttl),
    .s_ip_protocol(tx_ip_protocol),
    .s_ip_source_ip(tx_ip_source_ip),
    .s_ip_dest_ip(tx_ip_dest_ip),
    .s_ip_payload_axis_tdata(tx_ip_payload_axis_tdata),
    .s_ip_payload_axis_tvalid(tx_ip_payload_axis_tvalid),
    .s_ip_payload_axis_tready(tx_ip_payload_axis_tready),
    .s_ip_payload_axis_tlast(tx_ip_payload_axis_tlast),
    .s_ip_payload_axis_tuser(tx_ip_payload_axis_tuser),
    // IP frame output — not used
    .m_ip_hdr_valid(rx_ip_hdr_valid),
    .m_ip_hdr_ready(rx_ip_hdr_ready),
    .m_ip_eth_dest_mac(rx_ip_eth_dest_mac),
    .m_ip_eth_src_mac(rx_ip_eth_src_mac),
    .m_ip_eth_type(rx_ip_eth_type),
    .m_ip_version(rx_ip_version),
    .m_ip_ihl(rx_ip_ihl),
    .m_ip_dscp(rx_ip_dscp),
    .m_ip_ecn(rx_ip_ecn),
    .m_ip_length(rx_ip_length),
    .m_ip_identification(rx_ip_identification),
    .m_ip_flags(rx_ip_flags),
    .m_ip_fragment_offset(rx_ip_fragment_offset),
    .m_ip_ttl(rx_ip_ttl),
    .m_ip_protocol(rx_ip_protocol),
    .m_ip_header_checksum(rx_ip_header_checksum),
    .m_ip_source_ip(rx_ip_source_ip),
    .m_ip_dest_ip(rx_ip_dest_ip),
    .m_ip_payload_axis_tdata(rx_ip_payload_axis_tdata),
    .m_ip_payload_axis_tvalid(rx_ip_payload_axis_tvalid),
    .m_ip_payload_axis_tready(rx_ip_payload_axis_tready),
    .m_ip_payload_axis_tlast(rx_ip_payload_axis_tlast),
    .m_ip_payload_axis_tuser(rx_ip_payload_axis_tuser),
    // UDP frame input — ASCON encrypted payload goes here
    .s_udp_hdr_valid(tx_udp_hdr_valid),
    .s_udp_hdr_ready(tx_udp_hdr_ready),
    .s_udp_ip_dscp(tx_udp_ip_dscp),
    .s_udp_ip_ecn(tx_udp_ip_ecn),
    .s_udp_ip_ttl(tx_udp_ip_ttl),
    .s_udp_ip_source_ip(tx_udp_ip_source_ip),
    .s_udp_ip_dest_ip(tx_udp_ip_dest_ip),
    .s_udp_source_port(tx_udp_source_port),
    .s_udp_dest_port(tx_udp_dest_port),
    .s_udp_length(tx_udp_length),
    .s_udp_checksum(tx_udp_checksum),
    .s_udp_payload_axis_tdata(tx_udp_payload_axis_tdata),
    .s_udp_payload_axis_tvalid(tx_udp_payload_axis_tvalid),
    .s_udp_payload_axis_tready(tx_udp_payload_axis_tready),
    .s_udp_payload_axis_tlast(tx_udp_payload_axis_tlast),
    .s_udp_payload_axis_tuser(tx_udp_payload_axis_tuser),
    // UDP frame output — drained (not used for data)
    .m_udp_hdr_valid(rx_udp_hdr_valid),
    .m_udp_hdr_ready(rx_udp_hdr_ready),
    .m_udp_eth_dest_mac(rx_udp_eth_dest_mac),
    .m_udp_eth_src_mac(rx_udp_eth_src_mac),
    .m_udp_eth_type(rx_udp_eth_type),
    .m_udp_ip_version(rx_udp_ip_version),
    .m_udp_ip_ihl(rx_udp_ip_ihl),
    .m_udp_ip_dscp(rx_udp_ip_dscp),
    .m_udp_ip_ecn(rx_udp_ip_ecn),
    .m_udp_ip_length(rx_udp_ip_length),
    .m_udp_ip_identification(rx_udp_ip_identification),
    .m_udp_ip_flags(rx_udp_ip_flags),
    .m_udp_ip_fragment_offset(rx_udp_ip_fragment_offset),
    .m_udp_ip_ttl(rx_udp_ip_ttl),
    .m_udp_ip_protocol(rx_udp_ip_protocol),
    .m_udp_ip_header_checksum(rx_udp_ip_header_checksum),
    .m_udp_ip_source_ip(rx_udp_ip_source_ip),
    .m_udp_ip_dest_ip(rx_udp_ip_dest_ip),
    .m_udp_source_port(rx_udp_source_port),
    .m_udp_dest_port(rx_udp_dest_port),
    .m_udp_length(rx_udp_length),
    .m_udp_checksum(rx_udp_checksum),
    .m_udp_payload_axis_tdata(rx_udp_payload_axis_tdata),
    .m_udp_payload_axis_tvalid(rx_udp_payload_axis_tvalid),
    .m_udp_payload_axis_tready(rx_udp_payload_axis_tready),
    .m_udp_payload_axis_tlast(rx_udp_payload_axis_tlast),
    .m_udp_payload_axis_tuser(rx_udp_payload_axis_tuser),
    // Status
    .ip_rx_busy(),
    .ip_tx_busy(),
    .udp_rx_busy(),
    .udp_tx_busy(),
    .ip_rx_error_header_early_termination(),
    .ip_rx_error_payload_early_termination(),
    .ip_rx_error_invalid_header(),
    .ip_rx_error_invalid_checksum(),
    .ip_tx_error_payload_early_termination(),
    .ip_tx_error_arp_failed(),
    .udp_rx_error_header_early_termination(),
    .udp_rx_error_payload_early_termination(),
    .udp_tx_error_payload_early_termination(),
    // Configuration
    .local_mac(local_mac),
    .local_ip(local_ip),
    .gateway_ip(gateway_ip),
    .subnet_mask(subnet_mask),
    .clear_arp_cache(0)
);

// ================================================================
// Async FIFO: 125MHz → 62.5MHz
// UART RX (with tlast) → ASCON encrypt input
// ================================================================
axis_async_fifo #(
    .DEPTH(4096),
    .DATA_WIDTH(8),
    .KEEP_ENABLE(0),
    .LAST_ENABLE(1),
    .ID_ENABLE(0),
    .DEST_ENABLE(0),
    .USER_ENABLE(0),
    .FRAME_FIFO(0)
)
rx_async_fifo (
    // Write side (125MHz) — from UART packet framer
    .s_clk(clk),
    .s_rst(rst),
    .s_axis_tdata(uart_pkt_tdata),
    .s_axis_tkeep(0),
    .s_axis_tvalid(uart_pkt_tvalid),
    .s_axis_tready(uart_pkt_tready),
    .s_axis_tlast(uart_pkt_tlast),
    .s_axis_tid(0),
    .s_axis_tdest(0),
    .s_axis_tuser(0),

    // Read side (62.5MHz) — to ASCON wrapper
    .m_clk(clk_slow),
    .m_rst(rst_slow),
    .m_axis_tdata(slow_rx_tdata),
    .m_axis_tkeep(),
    .m_axis_tvalid(slow_rx_tvalid),
    .m_axis_tready(slow_rx_tready),
    .m_axis_tlast(slow_rx_tlast),
    .m_axis_tid(),
    .m_axis_tdest(),
    .m_axis_tuser(),

    .s_status_overflow(),
    .s_status_bad_frame(),
    .s_status_good_frame(),
    .m_status_overflow(),
    .m_status_bad_frame(),
    .m_status_good_frame()
);

// ================================================================
// ASCON Encryption Wrapper (62.5MHz domain)
// Input: plaintext from UART
// Output: nonce + AD + ciphertext + tag
// ================================================================
ascon_udp_wrapper ascon_wrap_inst (
    .clk       (clk_slow),
    .rst_n     (~rst_slow),

    .s_axis_tdata  (slow_rx_tdata),
    .s_axis_tvalid (slow_rx_tvalid),
    .s_axis_tready (slow_rx_tready),
    .s_axis_tlast  (slow_rx_tlast),

    .m_axis_tdata  (slow_tx_tdata),
    .m_axis_tvalid (slow_tx_tvalid),
    .m_axis_tready (slow_tx_tready),
    .m_axis_tlast  (slow_tx_tlast)
);

// ================================================================
// Async FIFO: 62.5MHz → 125MHz
// ASCON encrypted output → UDP TX
// ================================================================
axis_async_fifo #(
    .DEPTH(4096),
    .DATA_WIDTH(8),
    .KEEP_ENABLE(0),
    .LAST_ENABLE(1),
    .ID_ENABLE(0),
    .DEST_ENABLE(0),
    .USER_ENABLE(0),
    .FRAME_FIFO(0)
)
tx_async_fifo (
    // Write side (62.5MHz) — from ASCON wrapper
    .s_clk(clk_slow),
    .s_rst(rst_slow),
    .s_axis_tdata(slow_tx_tdata),
    .s_axis_tkeep(0),
    .s_axis_tvalid(slow_tx_tvalid),
    .s_axis_tready(slow_tx_tready),
    .s_axis_tlast(slow_tx_tlast),
    .s_axis_tid(0),
    .s_axis_tdest(0),
    .s_axis_tuser(0),

    // Read side (125MHz) — to UDP TX
    .m_clk(clk),
    .m_rst(rst),
    .m_axis_tdata(ascon_out_tdata),
    .m_axis_tkeep(),
    .m_axis_tvalid(ascon_out_tvalid),
    .m_axis_tready(ascon_out_tready),
    .m_axis_tlast(ascon_out_tlast),
    .m_axis_tid(),
    .m_axis_tdest(),
    .m_axis_tuser(),

    .s_status_overflow(),
    .s_status_bad_frame(),
    .s_status_good_frame(),
    .m_status_overflow(),
    .m_status_bad_frame(),
    .m_status_good_frame()
);

endmodule

`resetall