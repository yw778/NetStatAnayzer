package cn.bupt.netStateAnalyzer;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.DecimalFormat;

import java.util.ArrayList;


import org.jnetpcap.packet.JPacket;




import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;

import android.os.Message;
import android.telephony.TelephonyManager;
import android.telephony.cdma.CdmaCellLocation;
import android.telephony.gsm.GsmCellLocation;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import cn.bupt.netStateAnalyzer.analyze.OnReadComplete;
import cn.bupt.netStateAnalyzer.analyze.PacketReader;
import cn.bupt.netStateAnalyzer.analyze.ScoreStatisticsFactory;
import cn.bupt.netStateAnalyzer.analyze.ScoreStatisticsSuper;
import cn.bupt.netStateAnalyzer.pcap.DumpHelper;


/**
 * NetQuality 参数页面
 * 
 */
public class NetQualityIndicatorsActivity extends Activity {
	private static final String TAG = "NetQualityIndicatorsActivity";

	private static final int READ_COMPLETE = 1;
	public static final String LOCALIP = "localip";
	public static final String PKG_TYPE = "pkg_type";
	public static final String SET_WEIGHT = "set_weight";
	public static final int REQUEST_CODE_SETWEIGHT = 101;

	private DecimalFormat df = new DecimalFormat("#.###");

	public static PacketReader reader;
	public ArrayList<JPacket> packet;
	private String localIP;
	private int pkgType;
	public TextView loss;
	public TextView dns;
	public TextView tcp;
	public TextView resp;
	public TextView load;
	public TextView speed;
	public TextView traffic;
	public TextView thread;
	public TextView jitter;
	public TextView advertise;
	public TextView res_efficiency;
	public TextView ss;
	public TextView secureIndex;
	public TextView tradeTime;
	public TextView business_eff;
	
	private ProgressDialog progressDialog;
	private Message overMsg;
	
	public static int score;
	private ScoreStatisticsSuper statistics;

	private String[] ipList;
	public double latitude;
	public double longitude;
	public int age;
	public int user_score;
	public String sex;
	public String appName;
	public boolean anaFlag = false;


	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_net_quality_indicators);
		Resources res = getResources();
	    Drawable drawable = res.getDrawable(R.drawable.bkcolor);
	    this.getWindow().setBackgroundDrawable(drawable);
		Intent from = getIntent();
		localIP = from.getStringExtra(LOCALIP);
		pkgType = from.getIntExtra(PKG_TYPE, 0);
		ipList = from.getStringArrayExtra("IPLIST");
		age = from.getIntExtra("age", 0);
		user_score = from.getIntExtra("user_score", 0);
		sex = from.getStringExtra("sex");
		appName = from.getStringExtra("AppName");
		anaFlag = from.getBooleanExtra("anaFlag", false);
		Log.v(TAG, "localIP - " + localIP);
		Log.v(TAG, "pkgType - " + pkgType);
		Log.v("uploaddata", " " + appName);
			
		View layoutRetransmission = (View) findViewById(R.id.layout_retransmission);
		View layoutDns = (View) findViewById(R.id.layout_dns);
		View layoutTcpConnectionTime = (View) findViewById(R.id.layout_tcpconnectiontime);
		View layoutResponse = (View) findViewById(R.id.layout_responsetime);
		View layoutLoadTime = (View) findViewById(R.id.layout_loadtime);
		View layoutSpeed = (View) findViewById(R.id.layout_speed);
		View layoutTraffic = (View) findViewById(R.id.layout_traffic);
		View layoutThread = (View) findViewById(R.id.layout_thread);
		View layoutJitter = (View) findViewById(R.id.layout_jitter);
		View layoutAdvertise = (View) findViewById(R.id.layout_advertise);
		View layoutResEfficiency = (View) findViewById(R.id.layout_reseffictive);
		View layoutSecureIndex = (View) findViewById(R.id.layout_secureIndex);
		View layouttradeTime = (View) findViewById(R.id.layout_tradeTime);
		View layoutbusiness = (View) findViewById(R.id.layout_business_eff);
		
		layoutDns.setVisibility(View.VISIBLE);
		layoutTcpConnectionTime.setVisibility(View.VISIBLE);
		layoutRetransmission.setVisibility(View.VISIBLE);
		layoutTraffic.setVisibility(View.VISIBLE);
		layoutbusiness.setVisibility(View.VISIBLE);
		
		switch (pkgType) {
		case ScoreStatisticsSuper.WEB:
			layoutResponse.setVisibility(View.VISIBLE);
			layoutLoadTime.setVisibility(View.VISIBLE);
			layoutSpeed.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.DOWNLOAD:
			layoutLoadTime.setVisibility(View.VISIBLE);
			layoutThread.setVisibility(View.VISIBLE);
			layoutSpeed.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.VIDEO:
			layoutResponse.setVisibility(View.VISIBLE);
			layoutJitter.setVisibility(View.VISIBLE);
			layoutSpeed.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.GAME:
			layoutResponse.setVisibility(View.VISIBLE);
			layoutSpeed.setVisibility(View.VISIBLE);
			layoutAdvertise.setVisibility(View.VISIBLE);
			layoutResEfficiency.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.TRADE:
			layoutJitter.setVisibility(View.VISIBLE);
			layoutSecureIndex.setVisibility(View.VISIBLE);
			layouttradeTime.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.SOCIAL:
		default: break;
		}

		loss = (TextView) this.findViewById(R.id.textview_retransmission);
		dns = (TextView) this.findViewById(R.id.textview_dns);
		tcp = (TextView) this.findViewById(R.id.textview_tcpconnectiontime);
		resp = (TextView) this.findViewById(R.id.textview_responsetime);
		load = (TextView) this.findViewById(R.id.textview_loadtime);
		speed = (TextView) this.findViewById(R.id.textview_speed);
		traffic = (TextView) this.findViewById(R.id.textview_traffic);
		thread = (TextView) this.findViewById(R.id.textview_thread);
		jitter = (TextView) this.findViewById(R.id.textview_jitter);
		advertise = (TextView) this.findViewById(R.id.textview_advertise);
		res_efficiency = (TextView) this.findViewById(R.id.textview_resefficiency);
		secureIndex = (TextView) this.findViewById(R.id.textview_secureIndex);
		tradeTime = (TextView) this.findViewById(R.id.textview_tradeTime);
		ss = (TextView) this.findViewById(R.id.ss);
		business_eff = (TextView) this.findViewById(R.id.textview_business);
		
		statistics = ScoreStatisticsFactory.create(pkgType);

		Button detButt = (Button) this.findViewById(R.id.detail);
		detButt.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				Intent intent = new Intent();
				intent.setClass(NetQualityIndicatorsActivity.this,
						PacketDetailsActivity.class);
				startActivity(intent);
				NetQualityIndicatorsActivity.this.finish();
			}
		});
		Button saveBut = (Button) this.findViewById(R.id.save);
		saveBut.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				writeToLocal();
			}
		});
		Button setWeightBut = (Button) this.findViewById(R.id.set_weight);
		setWeightBut.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				setWeight();
			}
		});

		overMsg = new Message();
		overMsg.what = READ_COMPLETE;
		if(anaFlag){
			progressDialog = ProgressDialog.show(this, null,
					getString(R.string.processing_hint), true, false);
			new Thread( new Runnable() {
				@Override
					public void run() {
						reader = new PacketReader(ipList, localIP, DumpHelper.fileOutPath
								+ DumpHelper.fileName);
						reader.read(localIP, DumpHelper.fileOutPath
								+ DumpHelper.fileName, new OnReadComplete() {
							@Override
							public void onComplete() {
								score = statistics.totalScore(reader);
								handler.sendMessage(overMsg);
							}
						}, pkgType);
						
					}
			}).start();
			
		}
		else{
			handler.sendMessage(overMsg);
		}
	}

	/**
	 * 用户自定义不同类型的 结果的weight
	 */
	protected void setWeight() {
		Log.v(TAG, "setWeight");
		Intent intent = new Intent(this, SetWeightActivity.class);
		intent.putExtra(PKG_TYPE, pkgType);
		intent.putExtra(SET_WEIGHT, statistics.scoreWeight);
		startActivityForResult(intent, REQUEST_CODE_SETWEIGHT);
	}

	/**
	 * 存入文件
	 */
	public void writeToLocal() {
		File file = new File(Environment.getExternalStorageDirectory(),
				"reslut.txt");
		BufferedWriter writeToLocal = null;
		String appType = null;
		try {
			writeToLocal = new BufferedWriter(new OutputStreamWriter(
					new FileOutputStream(file, true)));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		StringBuilder sbTitle = new StringBuilder();
		sbTitle.append("Retransnission" + "\t").append("DNS Time" + "\t")
				.append("TCP Conn Time" + "\t").append("Response Time" + "\t")
				.append("Load Time" + "\t").append("Speed" + "\t")
				.append("Total Traffic" + "\t").append("Jitter" + "\t")
				.append("Thread Numbers" + "\t").append("Advertisement" + "\t")
				.append("Resource Efficiency" + "\t")
				.append("SecureIndex" + "\t").append("TradeTime" + "\t")
				.append("Score" + "\t").append("App Type" + "\t");

		StringBuilder sbDataCommon = new StringBuilder();
		sbDataCommon.append("\n" + loss.getText() + "\t")
				.append(dns.getText() + "\t").append(tcp.getText() + "\t");

		StringBuilder sbData = new StringBuilder();

		switch (pkgType) {
		case 0:
			appType = "web";
			sbData = sbDataCommon.append(resp.getText() + "\t")
					.append(load.getText() + "\t")
					.append(speed.getText() + "\t")
					.append(traffic.getText() + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append(ss.getText() + "\t")
					.append(appType + "\t");
			break;
		case 1:
			appType = "download";
			sbData = sbDataCommon.append("--" + "\t")
					.append(load.getText() + "\t")
					.append(speed.getText() + "\t").append("--" + "\t")
					.append("--" + "\t").append(thread.getText() + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append(ss.getText() + "\t").append(appType + "\t");
			break;
		case 2:
			appType = "video";
			sbData = sbDataCommon.append(resp.getText() + "\t")
					.append("--" + "\t").append(speed.getText() + "\t")
					.append("--" + "\t").append(jitter.getText() + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append(ss.getText() + "\t")
					.append(appType + "\t");
			break;
		case 3:
			appType = "trading";
			sbData = sbDataCommon.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append(traffic.getText() + "\t")
					.append(jitter.getText() + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append(secureIndex.getText() + "\t")
					.append(tradeTime.getText() + "\t")
					.append(ss.getText() + "\t").append(appType + "\t");
			break;
		case 4:
			appType = "game";
			sbData = sbDataCommon.append(resp.getText() + "\t")
					.append("--" + "\t").append(speed.getText() + "\t")
					.append(traffic.getText() + "\t").append("--" + "\t")
					.append("--" + "\t").append(advertise.getText() + "\t")
					.append(res_efficiency.getText() + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append(ss.getText() + "\t").append(appType + "\t");
			break;
		case 5:
			appType = "social";
			sbData = sbDataCommon.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append(traffic.getText() + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append("--" + "\t").append("--" + "\t")
					.append(ss.getText() + "\t").append(appType + "\t");
		default:
		}
		try {
			if (file.length() > 10) {
				writeToLocal.write(sbData.toString());
			} else {
				writeToLocal.write(sbTitle.toString());
				writeToLocal.write(sbData.toString());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			writeToLocal.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			writeToLocal.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		Toast toast = Toast.makeText(NetQualityIndicatorsActivity.this,
				"Stored in /sdcard/result.txt", Toast.LENGTH_SHORT);
		toast.show();
	}

	/**
	 * UI Handler
	 * 
	 */
	@SuppressLint("HandlerLeak")
	private Handler handler = new Handler() {

		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case READ_COMPLETE:
				loss.setText("" + PacketReader.pktLoss);
				dns.setText(df.format(0.001 * PacketReader.avrDns) + " ms");
				tcp.setText(df.format(0.001 * PacketReader.avrRtt) + " ms");
				resp.setText(df.format(0.001 * PacketReader.avrRes) + " ms");
				load.setText(df.format(1e-6 * PacketReader.avrTime) + " s");
				speed.setText(formatSpeed(8 * PacketReader.avrSpeed));
				traffic.setText(formatTraffic(PacketReader.traffic));
				thread.setText(String.valueOf(PacketReader.threadNum));
				jitter.setText(df.format(PacketReader.delayJitter));
				advertise.setText(PacketReader.advertise_num + "");
				res_efficiency.setText(PacketReader.res_efficiency + "%");
				secureIndex.setText(PacketReader.ssl * 100 + "%");
				tradeTime.setText(df.format(1e-6 * PacketReader.tradeTime) + "s");
				business_eff.setText(df.format(100 * PacketReader.businessEff) + "%");
				ss.setText("" + score);
				if (progressDialog != null) {
					progressDialog.cancel();
				}		
				break;
			default: break;
			}
		}
	};


	private String formatTraffic(long data) {
		return (data > 1000000) ? (df.format(data / 1048576.0)) + " MB"
				: ((data > 1000) ? (df.format(data / 1024.0)) + " KB"
						: data + " B");
	}


	private String formatSpeed(long data) {
		return (data > 1000000) ? (data / 1048576) + " Mbps"
				: ((data > 1000) ? (data / 1024) + " Kbps" : data + " bps");
	}
	
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if (keyCode == KeyEvent.KEYCODE_BACK) {
			this.setResult(1, null);
			this.finish();
			return true;
		}
		return false;
	}

	/**
	 * 用户设置完参数 sendmessage 给UI handler
	 * 
	 */
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
		switch (requestCode) {
		case REQUEST_CODE_SETWEIGHT:
			if (resultCode == Activity.RESULT_OK) {
				statistics.scoreWeight = intent.getParcelableExtra(SET_WEIGHT);
				Log.d(TAG, "weightDnsScore - "
						+ statistics.scoreWeight.weightDnsScore);
				score = statistics.totalScore(reader);
				Message msg = new Message();
				msg.what = READ_COMPLETE;
				handler.sendMessage(msg);
			}
		}
	}



}

