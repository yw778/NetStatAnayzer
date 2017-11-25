package cn.bupt.netStateAnalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;



import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.TaskStackBuilder;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.SimpleAdapter;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import cn.bupt.netStateAnalyzer.analyze.ScoreStatisticsSuper;
import cn.bupt.netStateAnalyzer.pcap.DumpHelper;
import cn.bupt.netStateAnalyzer.utils.Utils;


@SuppressLint("NewApi")
public class MainActivity extends Activity implements OnClickListener {
	private static final int MSG_UPDATE_IPLIST = 1;
	private static final int NOTIFICATION_ID = 101;

	private TextView tvFileLength;
	private Button btDumpStart;
	private Button btDumpStop;
	private Button btAnalyze;
	private Button btClearCache;
	private Spinner spPkgType;
	private Spinner spPkgName;
	private TextView tvIpList;
	private NotificationManager manager;
	private ArrayAdapter<CharSequence> adapterPkgType;
	private SimpleAdapter adapterPkgName;
	private List<HashMap<String, Object>> appList;
	private int appSelected = 0;
	public String sex;
	public int sex_select;
	public int age;
	public int score;

	private HashSet<String> ipList;
	private SharedPreferences sp;
	private DumpHelper helper;
	private String[] ipArray;

	private static HashMap<Integer, ArrayList<HashMap<String, Object>>> apps;

	private static String[] webKeyWords = { "browser", "chrome", "firefox",
			"浏览器" };
	private static String[] downloadKeyWords = { "download", "market", "下载",
			"市场" };
	private static String[] videoKeyWords = { "video", "youku", "kankan",
			"pplive", "storm", "视频" };
	private static String[] tradeKeyWords = { "pay", "bank", "交易", "银行" };
	private static String[] gameKeyWords = { "game", "游戏" };
	private static String[] socialKeyWords = { "qq", "tencent", "wechat",
			"weibo" };

	public boolean anaFlag = true;

	/**
	 * 注册及初始化activity
	 * 
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		Resources res = getResources();
	    Drawable drawable = res.getDrawable(R.drawable.bkcolor);
	    this.getWindow().setBackgroundDrawable(drawable);
		tvFileLength = (TextView) findViewById(R.id.textview_file_length);
		tvIpList = (TextView) findViewById(R.id.textview_ip_list);
		btDumpStart = (Button) findViewById(R.id.button_dump_start);
		btDumpStop = (Button) findViewById(R.id.button_dump_stop);
		btAnalyze = (Button) findViewById(R.id.button_analyze);
		btClearCache = (Button) findViewById(R.id.button_clear_cache);

		btDumpStart.setOnClickListener(this);
		btDumpStop.setOnClickListener(this);
		btAnalyze.setOnClickListener(this);
		btClearCache.setOnClickListener(this);
		

		sp = this.getSharedPreferences("IPs", Context.MODE_PRIVATE);
		ipList = (HashSet<String>) sp.getStringSet("IPSET",
				new HashSet<String>());
		setIpList();

		apps = new HashMap<Integer, ArrayList<HashMap<String, Object>>>();
		classifyApps(true);


		
		helper = new DumpHelper(MainActivity.this);
		
		//TODO CLEAR when 2nd 进入
		tvFileLength.setText(helper.getCaptureFileLength() + " B");
		

		spPkgType = (Spinner) findViewById(R.id.spinner_pkg_type);
		spPkgName = (Spinner) findViewById(R.id.spinner_pkg_name);

		adapterPkgType = ArrayAdapter.createFromResource(this,
				R.array.pkg_types, android.R.layout.simple_spinner_item);
		adapterPkgType
				.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spPkgType.setAdapter(adapterPkgType);
		spPkgType.setOnItemSelectedListener(new OnItemSelectedListener() {
			@Override
			public void onItemSelected(AdapterView<?> arg0, View arg1,
					int arg2, long arg3) {
				if (!apps.containsKey(arg2)) {
					apps.put(arg2, new ArrayList<HashMap<String, Object>>());
				}
				appList = apps.get(arg2);
				selectApp(appList);
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {
			}
		});

		manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
	}

	/**
	 * 选折app 并生放入hashMap
	 */
	public void selectApp(List<HashMap<String, Object>> list) {
		if (list.isEmpty()) {
			Log.i("App List", "Empty!");
			helper.setUidWithPkgName("");
		}
		adapterPkgName = new SimpleAdapter(this, list,
				android.R.layout.simple_list_item_1,
				new String[] { "app_title" }, new int[] { android.R.id.text1 });
		spPkgName.setAdapter(adapterPkgName);
		spPkgName.setOnItemSelectedListener(new OnItemSelectedListener() {
			@Override
			public void onItemSelected(AdapterView<?> arg0, View arg1,
					int arg2, long arg3) {
				appSelected = arg2;
				helper.setUidWithPkgName(appList.get(appSelected)
						.get("app_package").toString());
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {
			}
		});
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
	}

	/**
	 * 4个button 的listener
	 * 
	 */
	@Override
	public void onClick(View v) {
		NotificationCompat.Builder builder = new NotificationCompat.Builder(
				this).setSmallIcon(R.drawable.ic_launcher)
				.setContentTitle(getText(R.string.app_name))
				.setContentText(getText(R.string.notify_capturing))
				.setOngoing(true);
		switch (v.getId()) {
		case R.id.button_dump_start:
			if (isNetworkConnected()) {
				helper.clearIpSet();
				handler.post(runnable);
				helper.startCapture();
				Intent resultIntent = new Intent(this, MainActivity.class);
				TaskStackBuilder stackBuilder = TaskStackBuilder.create(this);
				stackBuilder.addParentStack(MainActivity.class);
				stackBuilder.addNextIntent(resultIntent);
				PendingIntent resultPendingIntent = stackBuilder
						.getPendingIntent(0, PendingIntent.FLAG_UPDATE_CURRENT);
				builder.setContentIntent(resultPendingIntent);
				manager.notify(NOTIFICATION_ID, builder.build());
				anaFlag = true;
				btDumpStart.setClickable(false);
				btAnalyze.setClickable(false);
				spPkgType.setClickable(false);
				spPkgName.setClickable(false);
				btClearCache.setClickable(false);
			
			} else {
				Toast.makeText(this, "Network is unavailable!",
						Toast.LENGTH_LONG).show();
			}
			break;
		case R.id.button_dump_stop:
			helper.stopCapture();
			manager.notify(NOTIFICATION_ID, builder.build());
			manager.cancel(NOTIFICATION_ID);
			

			LayoutInflater layoutInflater = LayoutInflater.from(this);
			View myLoginView = layoutInflater.inflate(R.layout.score, null);

			final RadioGroup rb = (RadioGroup) myLoginView
					.findViewById(R.id.gender);
			final EditText ageEdit = (EditText) myLoginView
					.findViewById(R.id.age);
			final EditText scoreEdit = (EditText) myLoginView
					.findViewById(R.id.score);

			handler.removeCallbacks(runnable);
			Message m = new Message();
			m.what = MSG_UPDATE_IPLIST;
			handler.sendMessage(m);

			Dialog alertDialog = new AlertDialog.Builder(this)
					.setTitle("Score for this experience")
					.setIcon(R.drawable.ic_launcher)
					.setView(myLoginView)
					.setPositiveButton("Confirm",
							new DialogInterface.OnClickListener() {

								@Override
								public void onClick(DialogInterface dialog,
										int which) {
									sex_select = rb.getCheckedRadioButtonId();
									if (sex_select == R.id.radioMale) {
										sex = "male";
									} else {
										sex = "female";
									}
									String age_get = ageEdit.getText()
											.toString();
									String score_get = scoreEdit.getText()
											.toString();
									age = Integer.parseInt((age_get.equals("")) ? "0"
											: age_get);
									score = Integer.parseInt((score_get
											.equals("")) ? "0" : score_get);
								}
							})
					.setNegativeButton("Cancel",
							new DialogInterface.OnClickListener() {

								@Override
								public void onClick(DialogInterface dialog,
										int which) {
									sex = null;
									age = 0;
									score = 0;
								}
							}).create();
			alertDialog.show();
			sp.edit().putStringSet("IPSET", ipList).commit();
			btDumpStart.setClickable(true);
			btAnalyze.setClickable(true);
			spPkgType.setClickable(true);
			spPkgName.setClickable(true);
			btClearCache.setClickable(true);
			break;
		case R.id.button_analyze:
			if (helper.getCaptureFileLength() == 0)
				break;
			Intent i = new Intent(MainActivity.this,
					NetQualityIndicatorsActivity.class);
			i.putExtra(NetQualityIndicatorsActivity.PKG_TYPE,
					spPkgType.getSelectedItemPosition());
			i.putExtra(NetQualityIndicatorsActivity.LOCALIP,
					helper.getLocalIp());
			if (!appList.isEmpty()) {
				i.putExtra("AppName",
						appList.get(appSelected).get("app_package").toString());
			}
			i.putExtra("age", age);
			i.putExtra("user_score", score);
			i.putExtra("sex", sex);
			if (ipList != null) {
				ipArray = ipList.toArray(new String[0]);
			}
			i.putExtra("IPLIST", ipArray);
			if (anaFlag) {
				i.putExtra("anaFlag", true);
				anaFlag = false;
			}
			startActivityForResult(i, 1);
			break;
		case R.id.button_clear_cache:
			Log.i("applist", appList.toString());
			if (!appList.isEmpty()) {
				Log.i("netUtils", "before");
				Utils.clearCache(this,
						appList.get(appSelected).get("app_package").toString());
			}
			break;
		default:
			break;
		}
	}


	/**
	 * UI Handler 
	 * 
	 */
	private Handler handler = new Handler() {
		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case MSG_UPDATE_IPLIST:
				ipList = helper.getIpSet();
				setIpList();
				tvFileLength.setText(helper.getCaptureFileLength() + " B");
				break;
			}
			super.handleMessage(msg);
		}
	};

	private void setIpList() {
		String lines = "";
		if (ipList.isEmpty()) {
			tvIpList.setText("Null");
		} else {
			for (String s : ipList) {
				lines += s + "\n";
			}
			tvIpList.setText(lines);
		}
	}

	/**
	 * Runnable 子线程 update ip
	 * 
	 */
	private Runnable runnable = new Runnable() {

		@Override
		public void run() {
			Log.i("Runnable", "Update ip set");
			helper.updateIpSet();
			Message m = new Message();
			m.what = MSG_UPDATE_IPLIST;
			handler.sendMessage(m);
			handler.postDelayed(runnable, 1000);
		}

	};

	public boolean isNetworkConnected() {
		ConnectivityManager connManager = (ConnectivityManager) this
				.getSystemService(CONNECTIVITY_SERVICE);
		NetworkInfo networkInfo = connManager.getActiveNetworkInfo();
		return networkInfo != null ? networkInfo.isConnected() : false;
	}

	
	@Override
	public void onBackPressed() {
		new AlertDialog.Builder(this)
				.setTitle(R.string.exit)
				.setPositiveButton(android.R.string.ok,
						new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog,
									int which) {
								handler.removeCallbacks(runnable);
								if (helper != null) {
									helper.stopCapture();
								}
								manager.cancel(NOTIFICATION_ID);
								MainActivity.this.finish();
							}
						})
				.setNegativeButton(android.R.string.cancel,
						new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog,
									int which) {
							}
						}).show();
	}

	/**
     * 初始化的时候生成app的list
	 * 
	 */
	private void classifyApps(boolean getSysPackages) {
		List<PackageInfo> pkgs = getPackageManager().getInstalledPackages(
				PackageManager.GET_PERMISSIONS
						| PackageManager.GET_UNINSTALLED_PACKAGES);
		int type;
		for (PackageInfo pkg : pkgs) {
			if (!getSysPackages
					&& (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) > 0) {
				continue;
			}
			if (DumpHelper.isNetworkNeeded(pkg)) {
				String label = pkg.applicationInfo.loadLabel(
						getPackageManager()).toString();
				String version = pkg.versionName;
				String packageName = pkg.packageName;
				HashMap<String, Object> map = new HashMap<String, Object>();
				map.put("app_title", label + " " + version);
				map.put("app_package", packageName);

				if (isThisApp(webKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.WEB;
				} else if (isThisApp(downloadKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.DOWNLOAD;
				} else if (isThisApp(videoKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.VIDEO;
				} else if (isThisApp(tradeKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.TRADE;
				} else if (isThisApp(gameKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.GAME;
				} else if (isThisApp(socialKeyWords, label, packageName)) {
					type = ScoreStatisticsSuper.SOCIAL;
				} else {
					type = ScoreStatisticsSuper.OTHER;
				}

				if (apps.containsKey(type)) {
					apps.get(type).add(map);
				} else {
					ArrayList<HashMap<String, Object>> list = new ArrayList<HashMap<String, Object>>();
					list.add(map);
					apps.put(type, list);
				}
			}
		}
	}

	@Override
	protected void onStop() {
		super.onStop();
	}

	private boolean isThisApp(String[] keyWords, String label,
			String packageName) {
		label = label.toLowerCase();
		packageName = packageName.toLowerCase();
		for (String s : keyWords) {
			if (label.contains(s) || packageName.contains(s)) {
				return true;
			}
		}
		return false;
	}
}
