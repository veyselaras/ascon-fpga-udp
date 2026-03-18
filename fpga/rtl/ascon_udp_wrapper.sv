`timescale 1ns / 1ps
`include "ascon-verilog/rtl/config.sv"

module ascon_udp_wrapper (
	input  logic       clk,
	input  logic       rst_n,

	// -------------------------------------------------------------------------
	// AXI Stream Giriş (FIFO - 8 bit) - FIFO'dan Gelen Veri
	// -------------------------------------------------------------------------
	input  logic [7:0] s_axis_tdata,
	input  logic       s_axis_tvalid,
	output logic       s_axis_tready,
	input  logic       s_axis_tlast,

	// -------------------------------------------------------------------------
	// AXI Stream Çıkış (TX - 8 bit) - MAC'e Giden Veri
	// -------------------------------------------------------------------------
	output logic [7:0] m_axis_tdata,
	output logic       m_axis_tvalid,
	input  logic       m_axis_tready,
	output logic       m_axis_tlast
);

	// -------------------------------------------------------------------------
	// İç Sinyaller (Ascon LWC Arayüzü İçin)
	// -------------------------------------------------------------------------
	logic        key_valid;
	logic [31:0] key;
	logic        key_ready;

	logic [31:0] bdi;
	logic [3:0]  bdi_valid;
	logic        bdi_ready;
	logic [3:0]  bdi_type;
	logic        bdi_eot;
	logic        bdi_eoi;

	logic [3:0]  mode;

	logic [31:0] bdo;
	logic        bdo_valid;
	logic [3:0]  bdo_type;
	logic        bdo_eot;
	logic        bdo_eoo;
	logic        bdo_ready;

	// -------------------------------------------------------------------------
	// Ascon LWC Core Instantiation
	// -------------------------------------------------------------------------
	ascon_core u_ascon (
		.clk        (clk),
		.rst        (~rst_n),
		.key        (key),
		.key_valid  (key_valid),
		.key_ready  (key_ready),
		.bdi        (bdi),
		.bdi_valid  (bdi_valid),
		.bdi_ready  (bdi_ready),
		.bdi_type   (data_t'(bdi_type)),
		.bdi_eot    (bdi_eot),
		.bdi_eoi    (bdi_eoi),
		.mode       (mode_t'(mode)),
		.bdo        (bdo),
		.bdo_valid  (bdo_valid),
		.bdo_ready  (bdo_ready),
		.bdo_type   (bdo_type),
		.bdo_eot    (bdo_eot),
		.bdo_eoo    (bdo_eoo),
		.auth       (),
		.auth_valid ()
	);

	// Sabit Test Değerleri
	localparam logic [127:0] FIXED_AD    = 128'h000000000000000000000000DDEEFF00;
	localparam logic [127:0] FIXED_KEY   = 128'h000102030405060708090A0B0C0D0E0F;
	localparam logic [127:0] FIXED_NONCE = 128'h0F0E0D0C0B0A09080706050403020100;

	// FSM State Tanımlamaları
	typedef enum logic [3:0] {
		S_IDLE              = 4'd0,
		S_GET_UDP_FIFO_DATA = 4'd1,
		S_SEND_MODE         = 4'd2,
		S_SEND_KEY          = 4'd3,
		S_SEND_NONCE        = 4'd4,
		S_SEND_AD           = 4'd5,
		S_SEND_PLAINTEXT    = 4'd6,
		S_GET_TAG           = 4'd7,
		S_SEND2TX           = 4'd8
	} state_t;

	typedef enum logic [1:0] {
		S_TX_NONCE    = 2'd0,
		S_TX_AD       = 2'd1,
		S_TX_ENC_DATA = 2'd2,
		S_TX_TAG      = 2'd3
	} state_send_t;

	state_t      state;
	state_send_t send_state;

	logic [7:0]  fifo_data [0:255];
	logic [7:0]  fifo_data_cnt;
	logic [7:0]  fifo_word_cnt;

	logic [1:0]  key_word_cnt;
	logic [1:0]  nonce_word_cnt;
	logic [1:0]  tag_word_cnt;

	logic [127:0] TAG;
	logic [7:0]   encrypted_data [0:255];
	logic [7:0]   encrypted_data_cnt;

	logic [8:0]  send_byte_cnt;
	logic [7:0]  pt_len;
	
	
	// Yeni register'lar tanımla (module başı):
	reg [31:0] bdo_captured;
	reg        bdo_capture_valid;
	reg [3:0]  bdi_valid_captured;



	// =========================================================================
	// Combinational Block — sadece çıkış sinyallerini sürüyor
	// Hiçbir register/array yazılmaz burada
	// =========================================================================
	always_comb begin
		// ----- Defaults (latch önleme) -----
		s_axis_tready = 1'b0;
		key_valid     = 1'b0;
		key           = 32'h0;
		mode          = 4'h0;
		bdi           = 32'h0;
		bdi_valid     = 4'h0;
		bdi_type      = 4'h0;
		bdi_eot       = 1'b0;
		bdi_eoi       = 1'b0;
		bdo_ready     = 1'b0;
		m_axis_tvalid = 1'b0;
		m_axis_tlast  = 1'b0;

		case (state)
			// ---------------------------------------------------------
			S_IDLE: begin
				s_axis_tready = 1'b1;
			end

			// ---------------------------------------------------------
			S_GET_UDP_FIFO_DATA: begin
				s_axis_tready = 1'b1;
			end

			// ---------------------------------------------------------
			// mode=1 ve key_valid=1 aynı cycle'da olmalı
			// Core idle_done'da ikisini birden kontrol ediyor
			S_SEND_MODE: begin
				mode      = 4'h1;
				key_valid = 1'b1;
				key       = FIXED_KEY[(key_word_cnt * 32) +: 32];
			end

			// ---------------------------------------------------------
			S_SEND_KEY: begin
				key_valid = 1'b1;
				key       = FIXED_KEY[(key_word_cnt * 32) +: 32];
			end

			// ---------------------------------------------------------
			S_SEND_NONCE: begin
				bdi_type  = 4'h1;  // D_NONCE
				bdi_valid = 4'hF;
				bdi       = FIXED_NONCE[(nonce_word_cnt * 32) +: 32];
				if (nonce_word_cnt == 2'b11)
					bdi_eot = 1'b1;
			end

			// ---------------------------------------------------------
			S_SEND_AD: begin
				bdi_type  = 4'h2;  // D_AD
				bdi_valid = 4'hF;
				bdi       = FIXED_AD[0+:32];
				bdi_eot   = 1'b1;
				bdi_eoi   = 1'b0;
			end

			// ---------------------------------------------------------
			S_SEND_PLAINTEXT: begin
				bdo_ready = 1'b1;
				bdi_type  = 4'h3;  // D_MSG
				bdi_valid = 4'hF;
				bdi_eoi   = 1'b0;
				bdi_eot   = 1'b0;

				if (fifo_data_cnt <= 4) begin
					bdi_eoi = 1'b1;
					bdi_eot = 1'b1;
					bdi     = {fifo_data[fifo_word_cnt+3],
							   fifo_data[fifo_word_cnt+2],
							   fifo_data[fifo_word_cnt+1],
							   fifo_data[fifo_word_cnt+0]};
					if (fifo_data_cnt >= 1)
						bdi_valid = 4'((5'b00001 << fifo_data_cnt) - 1'b1);
				end else begin
					bdi = {fifo_data[fifo_word_cnt+3],
						   fifo_data[fifo_word_cnt+2],
						   fifo_data[fifo_word_cnt+1],
						   fifo_data[fifo_word_cnt+0]};
				end
			end

			// ---------------------------------------------------------
			S_GET_TAG: begin
				bdo_ready = 1'b1;  // tag almak için hazır
			end

			// ---------------------------------------------------------
			S_SEND2TX: begin
				m_axis_tvalid = 1'b1;
				if (send_state == S_TX_TAG && send_byte_cnt == 9'd15)
					m_axis_tlast = 1'b1;
				end

			default: ;
		endcase
	end

	// =========================================================================
	// Sequential Block — state, sayaçlar, array yazmaları
	// =========================================================================
	always_ff @(posedge clk or negedge rst_n) begin
		if (!rst_n) begin
			state              <= S_IDLE;
			send_state         <= S_TX_NONCE;
			fifo_data_cnt      <= 8'd0;
			fifo_word_cnt      <= 8'd0;
			key_word_cnt       <= 2'd0;
			nonce_word_cnt     <= 2'd0;
			tag_word_cnt       <= 2'd0;
			encrypted_data_cnt <= 8'd0;
			send_byte_cnt      <= 9'd0;
			pt_len             <= 8'd0;
			TAG                <= 128'd0;
			m_axis_tdata 		 <= 8'd0;
			bdo_captured     	 <= 32'd0;
			bdo_capture_valid  <= 1'b0;
			bdi_valid_captured <= 4'd0;
		end else begin
			case (state)
				// ---------------------------------------------------------
				S_IDLE: begin
					if (s_axis_tvalid) begin
						fifo_data[fifo_data_cnt] <= s_axis_tdata;
						fifo_data_cnt            <= fifo_data_cnt + 8'd1;
						state                    <= S_GET_UDP_FIFO_DATA;
						if(s_axis_tlast) begin
							state	<= S_SEND_MODE;
							pt_len <= fifo_data_cnt + 8'd1;
						end
					end
				end

				// ---------------------------------------------------------
				S_GET_UDP_FIFO_DATA: begin
					if (s_axis_tvalid) begin
						fifo_data[fifo_data_cnt] <= s_axis_tdata;
						fifo_data_cnt            <= fifo_data_cnt + 8'd1;
						if (s_axis_tlast) begin
							pt_len <= fifo_data_cnt + 8'd1;
							state  <= S_SEND_MODE;
						end
					end
				end

				// ---------------------------------------------------------
				S_SEND_MODE: begin
					state <= S_SEND_KEY;
				end

				// ---------------------------------------------------------
				S_SEND_KEY: begin
					if (key_ready) begin
						key_word_cnt <= key_word_cnt + 2'd1;
						if (key_word_cnt == 2'b11) begin
							state        <= S_SEND_NONCE;
							key_word_cnt <= 2'd0;
						end
					end
				end

				// ---------------------------------------------------------
				S_SEND_NONCE: begin
					if (bdi_ready) begin
						nonce_word_cnt <= nonce_word_cnt + 2'd1;
						if (nonce_word_cnt == 2'b11) begin
							state          <= S_SEND_AD;
							nonce_word_cnt <= 2'd0;
						end
					end
				end

				// ---------------------------------------------------------
				S_SEND_AD: begin
					if (bdi_ready) begin
						state <= S_SEND_PLAINTEXT;
					end
				end

				// ---------------------------------------------------------
				S_SEND_PLAINTEXT: begin
					// Ciphertext yakalama (array yazma)
					 if (bdo_valid && bdo_type == 4'h3) begin
						  bdo_captured      <= bdo;
						  bdo_capture_valid <= 1'b1;
						  bdi_valid_captured <= bdi_valid;
					 end else begin
						  bdo_capture_valid <= 1'b0;
					 end

					// Cycle 2: encrypted_data'ya yaz (bir cycle sonra)
					 if (bdo_capture_valid) begin
						  encrypted_data[encrypted_data_cnt]     <= bdo_captured[7:0];
						  encrypted_data[encrypted_data_cnt + 1] <= bdo_captured[15:8];
						  encrypted_data[encrypted_data_cnt + 2] <= bdo_captured[23:16];
						  encrypted_data[encrypted_data_cnt + 3] <= bdo_captured[31:24];
						  encrypted_data_cnt <= encrypted_data_cnt + bdi_valid_captured[3] + bdi_valid_captured[2] + bdi_valid_captured[1] + bdi_valid_captured[0];
					 end

					 // Plaintext word ilerleme (bu kısım aynı kalır)
					 if (fifo_data_cnt <= 4) begin
						  if (bdi_ready) begin
								state         <= S_GET_TAG;
								fifo_data_cnt <= 8'd0;
								fifo_word_cnt <= 8'd0;
						  end
					 end else begin
						  if (bdi_ready) begin
								fifo_word_cnt <= fifo_word_cnt + 8'd4;
								fifo_data_cnt <= fifo_data_cnt - 8'd4;
						  end
					 end
				end

				// ---------------------------------------------------------
				S_GET_TAG: begin
					 if (bdo_capture_valid) begin
						  encrypted_data[encrypted_data_cnt]     <= bdo_captured[7:0];
						  encrypted_data[encrypted_data_cnt + 1] <= bdo_captured[15:8];
						  encrypted_data[encrypted_data_cnt + 2] <= bdo_captured[23:16];
						  encrypted_data[encrypted_data_cnt + 3] <= bdo_captured[31:24];
						  encrypted_data_cnt <= encrypted_data_cnt + bdi_valid_captured[3] + bdi_valid_captured[2] + bdi_valid_captured[1] + bdi_valid_captured[0];
						  bdo_capture_valid  <= 1'b0;
					 end
					if (bdo_valid && bdo_type == 4'h4) begin
						TAG[32 * tag_word_cnt +: 32] <= bdo;
						tag_word_cnt                 <= tag_word_cnt + 2'd1;
						if (tag_word_cnt == 2'b11) begin
							state      <= S_SEND2TX;
							send_state <= S_TX_NONCE;
							m_axis_tdata <= FIXED_NONCE[0 +: 8];
						end
					end
				end

				// ---------------------------------------------------------
				S_SEND2TX: begin
					case (send_state)
						S_TX_NONCE: begin
							if (m_axis_tready) begin
								if (send_byte_cnt == 9'd15) begin
									send_byte_cnt <= 9'd0;
									send_state    <= S_TX_AD;
									m_axis_tdata  <= FIXED_AD[0 +: 8];
								end else begin
									send_byte_cnt <= send_byte_cnt + 9'd1;
									m_axis_tdata  <= FIXED_NONCE[(send_byte_cnt + 1) * 8 +: 8];
								end
							end
						end

						S_TX_AD: begin
							if (m_axis_tready) begin
								if (send_byte_cnt == 9'd3) begin
									send_byte_cnt <= 9'd0;
									if (pt_len == 8'd0) begin
										send_state   <= S_TX_TAG;
										m_axis_tdata <= TAG[0 +: 8];
									end else begin
										send_state   <= S_TX_ENC_DATA;
										m_axis_tdata <= encrypted_data[0];
									end
								end else begin
									send_byte_cnt <= send_byte_cnt + 9'd1;
									m_axis_tdata  <= FIXED_AD[(send_byte_cnt + 1) * 8 +: 8];
								end
							end
						end

						S_TX_ENC_DATA: begin
							if (m_axis_tready) begin
								if (send_byte_cnt == {1'b0, pt_len} - 9'd1) begin
									send_byte_cnt <= 9'd0;
									send_state    <= S_TX_TAG;
									m_axis_tdata  <= TAG[0 +: 8];
								end else begin
									send_byte_cnt <= send_byte_cnt + 9'd1;
									m_axis_tdata  <= encrypted_data[send_byte_cnt + 1];
								end
							end
						end

						S_TX_TAG: begin
							if (m_axis_tready) begin
								if (send_byte_cnt == 9'd15) begin
									state              <= S_IDLE;
									send_byte_cnt      <= 9'd0;
									send_state         <= S_TX_NONCE;
									fifo_data_cnt      <= 8'd0;
									fifo_word_cnt      <= 8'd0;
									encrypted_data_cnt <= 8'd0;
									tag_word_cnt       <= 2'd0;
								end else begin
									send_byte_cnt <= send_byte_cnt + 9'd1;
									m_axis_tdata  <= TAG[(send_byte_cnt + 1) * 8 +: 8];
								end
							end
						end

						default: ;
					endcase
				end

				default: state <= S_IDLE;
			endcase
		end
	end

endmodule
