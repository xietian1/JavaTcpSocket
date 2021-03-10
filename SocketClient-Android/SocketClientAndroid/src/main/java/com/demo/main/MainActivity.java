package com.demo.main;

import com.jzj.socket.SocketTransceiver;
import com.jzj.socket.TcpClient;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

	private Button bnConnect;
	private TextView txReceive;
	private EditText edIP, edPort, edData;
	private String data_100 = "10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KBDATA10KB";

	private Handler handler = new Handler(Looper.getMainLooper());

	private TcpClient client = new TcpClient() {

		@Override
		public void onConnect(SocketTransceiver transceiver) {
			refreshUI(true);
		}

		@Override
		public void onDisconnect(SocketTransceiver transceiver) {
			refreshUI(false);
		}

		@Override
		public void onConnectFailed() {
			handler.post(new Runnable() {
				@Override
				public void run() {
					Toast.makeText(MainActivity.this, "Connect Fail",
							Toast.LENGTH_SHORT).show();
				}
			});
		}

		@Override
		public void onReceive(SocketTransceiver transceiver, final String s) {
			handler.post(new Runnable() {
				@Override
				public void run() {
					txReceive.append(s);
				}
			});
		}
	};

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		this.findViewById(R.id.bn_send).setOnClickListener(this);
		bnConnect = (Button) this.findViewById(R.id.bn_connect);
		bnConnect.setOnClickListener(this);

		edIP = (EditText) this.findViewById(R.id.ed_ip);
		edPort = (EditText) this.findViewById(R.id.ed_port);
		edData = (EditText) this.findViewById(R.id.ed_dat);
		txReceive = (TextView) this.findViewById(R.id.tx_receive);
		txReceive.setOnClickListener(this);

		refreshUI(false);
	}

	@Override
	public void onStop() {
		client.disconnect();
		super.onStop();
	}

	@Override
	public void onClick(View v) {
		switch (v.getId()) {
		case R.id.bn_connect:
			connect();
			break;
		case R.id.bn_send:
			sendStr();
			break;
		case R.id.tx_receive:
			clear();
			break;
		}
	}

	/**
	 * 刷新界面显示
	 * 
	 * @param isConnected
	 */
	private void refreshUI(final boolean isConnected) {
		handler.post(new Runnable() {
			@Override
			public void run() {
				edPort.setEnabled(!isConnected);
				edIP.setEnabled(!isConnected);
				bnConnect.setText(isConnected ? "Disconnect" : "Connect");
			}
		});
	}

	/**
	 * 设置IP和端口地址,连接或断开
	 */
	private void connect() {
		if (client.isConnected()) {
			// 断开连接
			client.disconnect();
			return ;
		}
		if (!client.isConnected()){
			try {
				String hostIP = edIP.getText().toString();
				int port = Integer.parseInt(edPort.getText().toString());
				client.connect(hostIP, port);
			} catch (NumberFormatException e) {
				Toast.makeText(this, "Port Error", Toast.LENGTH_SHORT).show();
				e.printStackTrace();
				return ;
			}

			Handler handler = new Handler();
			handler.postDelayed(new Runnable() {
				@Override
				public void run() {
					//Send 10KB data after connecting to the server
					String tosend = "";
					//100 * 100 = 10,000 (1kb)
					for (int i = 0; i < 100; i++) {
						tosend += data_100;
					}
					Log.i("Tosend:", tosend);
					client.getTransceiver().send(tosend);
				}
			}, 200);
		}


		/*
		else {
			try {
				String hostIP = edIP.getText().toString();
				int port = Integer.parseInt(edPort.getText().toString());
				client.connect(hostIP, port);
			} catch (NumberFormatException e) {
				Toast.makeText(this, "Port Error", Toast.LENGTH_SHORT).show();
				e.printStackTrace();
			}
		}
		*/

	}

	/**
	 * 发送数据
	 */
	private void sendStr() {
		try {
			String data = edData.getText().toString();
			client.getTransceiver().send(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 清空接收框
	 */
	private void clear() {
		new AlertDialog.Builder(this).setTitle("确认清除?")
				.setNegativeButton("取消", null)
				.setPositiveButton("确认", new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						txReceive.setText("");
					}
				}).show();
	}
}
