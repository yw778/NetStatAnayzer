package cn.bupt.netStateAnalyzer;

import java.util.ArrayList;
import java.util.HashMap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;

import android.content.Context;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.TextView;
import cn.bupt.netStateAnalyzer.analyze.PacketReader;


/**
 * PacketDetails适配器
 * 
 * 
 */

public class PacketDetailsAdapter extends ArrayAdapter<JPacket> {
	
	private static HashMap<String, JHeader> map;
	private ArrayList<JPacket> packets;
	private LayoutInflater mInflater;
	private static Ip4 ip4 = new Ip4();
	private static Ip6 ip6 = new Ip6();
	private static Tcp tcp = new Tcp();
	private static Udp udp = new Udp();
	private static Icmp icmp = new Icmp();
	private static Http http = new Http();
	private static Rtp rtp = new Rtp();
	
	public PacketDetailsAdapter(Context context, int resource, ArrayList<JPacket> packets) {
		super(context, resource, packets);
		setMap();
		this.packets = packets;
		mInflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
	}
	
	@Override
	public View getView(int position, View convertView, ViewGroup parent) {
		View v = convertView;
		ViewHolder holder = null;
		if (v == null) {
			v = mInflater.inflate(R.layout.list_item, null);
			holder = new ViewHolder();
			holder.setView(v);
			v.setTag(holder);
		} else {
			holder = (ViewHolder) v.getTag();
		}	
		setValue(holder, position);	
		return v;
	}
	
	private void setValue(ViewHolder vh, int position) {
		JPacket p = packets.get(position);
		if (p != null) {
			vh.packet.setText(Integer.toString(position + 1));	
			vh.len.setText(Integer.toString(p.getPacketWirelen()));
			if (PacketReader.rttMap.containsKey(position)) {
				vh.delay.setText(PacketReader.rttMap.get(position).toString());
			} else {
				vh.delay.setText("---");
			}
			if (PacketReader.retTable[position]) { 
				vh.ll1.setBackgroundColor(Color.BLACK);
				vh.packet.setTextColor(Color.RED);
			} else {
				vh.ll1.setBackgroundColor(Color.rgb(0x1E, 0x90, 0xFF));
				vh.packet.setTextColor(Color.BLACK);
			}
			if (p.hasHeader(Icmp.ID)) {
				vh.setNetProtocol(p, "ICMP");
			} else if (p.hasHeader(Ip4.ID) || p.hasHeader(Ip6.ID)) {
				String s = "";
				if (p.hasHeader(Ip4.ID)) {
					s = "IPv4";
				} else {
					s = "IPv6";
				}
				vh.setNetProtocol(p, s);
				if (p.hasHeader(Tcp.ID)) {
					vh.setTransProtocol(p,"TCP");
					
					if (p.hasHeader(Http.ID)) {
						vh.setAppProtocol(p,"HTTP");
					} else if (p.hasHeader(Rtp.ID)) {
						vh.setAppProtocol(p,"RTP");
					} else {
						vh.setAppProtocol(p,"unknow");
					}
				} else if (p.hasHeader(Udp.ID)) {
					vh.setTransProtocol(p,"UDP");
					if (p.hasHeader(Rtp.ID)) {
						vh.setAppProtocol(p,"RTP");
					}
				}
			} 
		}		
	}
	
	private void setMap() {
		map = new HashMap<String, JHeader>();
		map.put("IPv4", ip4);
		map.put("IPv6", ip6);
		map.put("TCP", tcp);
		map.put("UDP", udp);
		map.put("ICMP", icmp);
		map.put("HTTP", http);
		map.put("RTP", rtp);
		
	}
	
	static class ViewHolder {
		public LinearLayout ll1;
		public TextView packet;
		public TextView len;
		public TextView delay;
		public TextView appProtocol;
		public TextView transProtocol;
		public TextView srcPort;
		public TextView dstPort;
		public TextView netProtocol;
		public TextView srcAddr;
		public TextView dstAddr;
		
		public void setView(View v) {
			ll1 = (LinearLayout) v.findViewById(R.id.ll1);
			packet = (TextView) v.findViewById(R.id.packet);
			len = (TextView) v.findViewById(R.id.len);
			delay = (TextView) v.findViewById(R.id.delay);
			appProtocol = (TextView) v.findViewById(R.id.appProtocol);
			transProtocol = (TextView) v.findViewById(R.id.transProtocol);
			srcPort = (TextView) v.findViewById(R.id.srcPort);
			dstPort = (TextView) v.findViewById(R.id.dstPort);
			netProtocol = (TextView) v.findViewById(R.id.netProtocol);
			srcAddr = (TextView) v.findViewById(R.id.srcAddr);
			dstAddr = (TextView) v.findViewById(R.id.dstAddr);
		}
		
		private void setNetProtocol(JPacket p, String protocol) {
			netProtocol.setText(protocol);
			p.getHeader(map.get(protocol));
			if (protocol.equals("ICMP")) {		
				srcAddr.setText("unknow");
				dstAddr.setText("unknow");
			} else if (protocol.equals("IPv4")) {
				srcAddr.setText(FormatUtils.ip(ip4.source()));
				dstAddr.setText(FormatUtils.ip(ip4.destination()));
			} else if (protocol.equals("IPv6")) {
				srcAddr.setText(FormatUtils.asStringIp6(ip6.source(),true));
				dstAddr.setText(FormatUtils.asStringIp6(ip6.destination(),true));
			}
		}
		
		private void setTransProtocol(JPacket p, String protocol) {
			transProtocol.setText(protocol);
			p.getHeader(map.get(protocol));
			if (protocol.equals("TCP")) {		
				srcPort.setText(Integer.toString(tcp.source()));
				dstPort.setText(Integer.toString(tcp.destination()));
			} else if (protocol.equals("UDP")) {
				srcPort.setText(Integer.toString(udp.source()));
				dstPort.setText(Integer.toString(udp.destination()));
			}
		}
		
		private void setAppProtocol(JPacket p, String protocol) {
			appProtocol.setText(protocol);
			if (!protocol.equals("unknow")) {
				netProtocol.setText(protocol);
				p.getHeader(map.get(protocol));	
			}
		}
	}

	
}