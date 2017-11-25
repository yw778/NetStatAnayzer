package cn.bupt.netStateAnalyzer;

import java.util.ArrayList;

import org.jnetpcap.packet.JPacket;


import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.view.KeyEvent;
import android.widget.ListView;
import android.widget.TextView;
import cn.bupt.netStateAnalyzer.analyze.PacketReader;

/**
 * PacketReader
 * 显示抓包信息
 * 
 * 
 */
public class PacketDetailsActivity extends Activity {

	private TextView tv;
	private ListView lv;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.packets_list);
		Resources res = getResources();
		Drawable drawable = res.getDrawable(R.drawable.bkcolor);
		this.getWindow().setBackgroundDrawable(drawable);
		tv = (TextView) this.findViewById(R.id.numPkt);
		lv = (ListView) this.findViewById(R.id.pktList);
		
		ArrayList<JPacket> packets = PacketReader.packets;
		PacketDetailsAdapter adapter = new PacketDetailsAdapter(this,R.layout.list_item,packets);
		lv.setAdapter(adapter);
		tv.setText("" + packets.size());
	}
	
	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if (keyCode == KeyEvent.KEYCODE_BACK) {
			Intent intent = new Intent(this, NetQualityIndicatorsActivity.class);
			this.startActivity(intent);
			this.finish(); 
			return true;
		}
		return false;
	}

}
