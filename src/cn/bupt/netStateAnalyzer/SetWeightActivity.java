package cn.bupt.netStateAnalyzer;

import android.app.Activity;
import android.content.Intent;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import cn.bupt.netStateAnalyzer.analyze.ScoreStatisticsSuper;
import cn.bupt.netStateAnalyzer.analyze.ScoreWeight;


/**
 * 用户自定义参数
 * 
 * 
 */
public class SetWeightActivity extends Activity implements OnClickListener {
    public static final String TAG = "SetWeightActivity";

    private int pkgType;
    private ScoreWeight scoreWeight;
    private EditText etRetransmission;
    private EditText etDnsTime;
    private EditText etTcpConnectTime;
    private EditText etResponseTime;
    private EditText etLoadTime;
    private EditText etSpeed;
    private EditText etTraffic;
    private EditText etThread;
    private EditText etJitter;
    private EditText etAdvertise;
    private EditText etResEfficiency;
    private EditText etSecureIndex;
    private EditText ettradeTime;

    private Button btSubmit;
    private Button btCancel;

 
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_set_weight);
        Resources res = getResources();
	    Drawable drawable = res.getDrawable(R.drawable.bkcolor);
	    this.getWindow().setBackgroundDrawable(drawable);
        Intent intent = getIntent();
        pkgType = intent.getIntExtra(NetQualityIndicatorsActivity.PKG_TYPE, -1);
        scoreWeight = intent
                .getParcelableExtra(NetQualityIndicatorsActivity.SET_WEIGHT);

        View layoutRetransmission = (View) findViewById(R.id.layout_set_retransmission);
        View layoutDns = (View) findViewById(R.id.layout_set_dns);
        View layoutTcpConnectionTime = (View) findViewById(R.id.layout_set_tcpconnectiontime);
        View layoutResponse = (View) findViewById(R.id.layout_set_responsetime);
        View layoutLoadTime = (View) findViewById(R.id.layout_set_loadtime);
        View layoutSpeed = (View) findViewById(R.id.layout_set_speed);
        View layoutTraffic = (View) findViewById(R.id.layout_set_traffic);
        View layoutThread = (View) findViewById(R.id.layout_set_thread);
        View layoutJitter = (View) findViewById(R.id.layout_set_jitter);
        View layoutAdvertise = (View) findViewById(R.id.layout_advertise);
		View layoutResEfficiency = (View) findViewById(R.id.layout_reseffictive);
		View layoutSecureIndex = (View) findViewById(R.id.layout_secureIndex);
		View layouttradeTime = (View) findViewById(R.id.layout_tradeTime);

        switch (pkgType) {
        case ScoreStatisticsSuper.WEB:
            layoutDns.setVisibility(View.VISIBLE);
            layoutTcpConnectionTime.setVisibility(View.VISIBLE);
            layoutResponse.setVisibility(View.VISIBLE);
            layoutLoadTime.setVisibility(View.VISIBLE);
            layoutSpeed.setVisibility(View.VISIBLE);
            layoutTraffic.setVisibility(View.VISIBLE);
            break;
        case ScoreStatisticsSuper.DOWNLOAD:
            layoutDns.setVisibility(View.VISIBLE);
            layoutTcpConnectionTime.setVisibility(View.VISIBLE);
            layoutLoadTime.setVisibility(View.VISIBLE);
            layoutThread.setVisibility(View.VISIBLE);
            layoutSpeed.setVisibility(View.VISIBLE);
            layoutRetransmission.setVisibility(View.VISIBLE);
            break;
        case ScoreStatisticsSuper.VIDEO:
            layoutDns.setVisibility(View.VISIBLE);
            layoutTcpConnectionTime.setVisibility(View.VISIBLE);
            layoutResponse.setVisibility(View.VISIBLE);
            layoutJitter.setVisibility(View.VISIBLE);
            layoutSpeed.setVisibility(View.VISIBLE);
            layoutRetransmission.setVisibility(View.VISIBLE);
            break;
        case ScoreStatisticsSuper.GAME:
			layoutDns.setVisibility(View.VISIBLE);
			layoutTcpConnectionTime.setVisibility(View.VISIBLE);
			layoutResponse.setVisibility(View.VISIBLE);
			layoutSpeed.setVisibility(View.VISIBLE);
			layoutTraffic.setVisibility(View.VISIBLE);
			layoutRetransmission.setVisibility(View.VISIBLE);
			layoutAdvertise.setVisibility(View.VISIBLE);
			layoutResEfficiency.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.TRADE:
			layoutDns.setVisibility(View.VISIBLE);
			layoutTcpConnectionTime.setVisibility(View.VISIBLE);
			layoutJitter.setVisibility(View.VISIBLE);
			layoutRetransmission.setVisibility(View.VISIBLE);
			layoutSecureIndex.setVisibility(View.VISIBLE);
			layouttradeTime.setVisibility(View.VISIBLE);
			layoutTraffic.setVisibility(View.VISIBLE);
			break;
		case ScoreStatisticsSuper.SOCIAL:
			layoutDns.setVisibility(View.VISIBLE);
			layoutTcpConnectionTime.setVisibility(View.VISIBLE);
			layoutRetransmission.setVisibility(View.VISIBLE);
			layoutTraffic.setVisibility(View.VISIBLE);
            break;
        default:
        }

        etRetransmission = (EditText) findViewById(R.id.edittext_retransmission);
        etDnsTime = (EditText) findViewById(R.id.edittext_dns);
        etTcpConnectTime = (EditText) findViewById(R.id.edittext_tcpconnectiontime);
        etResponseTime = (EditText) findViewById(R.id.edittext_responsetime);
        etLoadTime = (EditText) findViewById(R.id.edittext_loadtime);
        etSpeed = (EditText) findViewById(R.id.edittext_speed);
        etTraffic = (EditText) findViewById(R.id.edittext_traffic);
        etThread = (EditText) findViewById(R.id.edittext_thread);
        etJitter = (EditText) findViewById(R.id.edittext_jitter);
        etAdvertise = (EditText) findViewById(R.id.edittext_advertise);
        etResEfficiency = (EditText) findViewById(R.id.edittext_ResEfficiency);
        etSecureIndex = (EditText) findViewById(R.id.edittext_SecureIndex);
        ettradeTime = (EditText) findViewById(R.id.edittext_tradeTime);

        etRetransmission.setText(String
                .valueOf(scoreWeight.weightPacketlossScore));
        etDnsTime.setText(String.valueOf(scoreWeight.weightDnsScore));
        etTcpConnectTime.setText(String.valueOf(scoreWeight.weightTcpScore));
        etResponseTime.setText(String.valueOf(scoreWeight.weightRespScore));
        etLoadTime.setText(String.valueOf(scoreWeight.weightLoadScore));
        etSpeed.setText(String.valueOf(scoreWeight.weightSpeedScore));
        etTraffic.setText(String.valueOf(scoreWeight.weightTrafficScore));
        etThread.setText(String.valueOf(scoreWeight.weightMultithreadScore));
        etJitter.setText(String.valueOf(scoreWeight.weightDelayjitterScore));
        etAdvertise.setText(String.valueOf(scoreWeight.weightAdvertise));
        etResEfficiency.setText(String.valueOf(scoreWeight.weightEfficiency));
        etSecureIndex.setText(String.valueOf(scoreWeight.weightSecureScore));
        ettradeTime.setText(String.valueOf(scoreWeight.weightTimeScore));
        
        btSubmit = (Button) findViewById(R.id.button_set);
        btCancel = (Button) findViewById(R.id.button_cancel);
        btSubmit.setOnClickListener(this);
        btCancel.setOnClickListener(this);
    }

    /**
     * 成功 后返回数据
     * 
     */
    @Override
    public void onClick(View v) {
        switch (v.getId()) {
        case R.id.button_cancel:
            setResult(Activity.RESULT_CANCELED, new Intent());
            finish();
        case R.id.button_set:
            Intent intent = new Intent();
            scoreWeight.weightPacketlossScore = Double
                    .parseDouble(etRetransmission.getText().toString());
            scoreWeight.weightDnsScore = Double.parseDouble(etDnsTime.getText()
                    .toString());
            scoreWeight.weightTcpScore = Double.parseDouble(etTcpConnectTime
                    .getText().toString());
            scoreWeight.weightRespScore = Double.parseDouble(etResponseTime
                    .getText().toString());
            scoreWeight.weightLoadScore = Double.parseDouble(etLoadTime
                    .getText().toString());
            scoreWeight.weightSpeedScore = Double.parseDouble(etSpeed.getText()
                    .toString());
            scoreWeight.weightTrafficScore = Double.parseDouble(etTraffic
                    .getText().toString());
            scoreWeight.weightMultithreadScore = Double.parseDouble(etThread
                    .getText().toString());
            scoreWeight.weightDelayjitterScore = Double.parseDouble(etJitter
                    .getText().toString());
            scoreWeight.weightAdvertise = Double.parseDouble(etAdvertise.getText().toString());
            scoreWeight.weightEfficiency = Double.parseDouble(etResEfficiency.getText().toString());
            scoreWeight.weightSecureScore = Double.parseDouble(etSecureIndex.getText().toString());
            scoreWeight.weightTimeScore = Double.parseDouble(ettradeTime.getText().toString());

            intent.putExtra(NetQualityIndicatorsActivity.SET_WEIGHT,
                    scoreWeight);
            setResult(Activity.RESULT_OK, intent);
            finish();
        }
    }
}
