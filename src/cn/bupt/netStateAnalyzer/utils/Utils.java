package cn.bupt.netStateAnalyzer.utils;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

public class Utils {
    private static final String TAG = "netUtils";
    
    /*
     * clear cache
     */
    public static void clearCache(Context context, String pkgName) {
        Log.v(TAG, "clearCache");
        String cmdClearCacheInData = "rm -r /data/data/" + pkgName
                + "/cache/*;echo \"Data cache cleared\"\n";
        String cmdClearCacheInSdcard = "rm -r /sdcard/Android/data/" + pkgName
                + "/cache/*;echo \"Sdcard cache cleared\"\n";

        try {
            Process rootProcess = Runtime.getRuntime().exec("su");
            DataOutputStream os = new DataOutputStream(
                    rootProcess.getOutputStream());
            os.writeBytes(cmdClearCacheInData);
            os.writeBytes(cmdClearCacheInSdcard);
            os.flush();
            os.close();
            // Toast.makeText(context, "clear cache", Toast.LENGTH_LONG).show();

            InputStreamReader ir = new InputStreamReader(
                    rootProcess.getInputStream());
            LineNumberReader input = new LineNumberReader(ir);
            String line;
            rootProcess.waitFor();
            while ((line = input.readLine()) != null) {
                Log.d(TAG, line);
               // Log.d(TAG, ""+input.getLineNumber());
                Toast.makeText(context, line, Toast.LENGTH_SHORT).show();
            }
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
        } catch (InterruptedException e) {
            Log.e(TAG, "InterruptedException: " + e.getMessage());
        }
    }
}
