package com.linonly.videoeditor;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.pm.ConfigurationInfo;
import android.os.Build;

public class APP extends Application
{

	private static Context mContext;
	private static APP mApplication;
	public static int width;
	public static int height;
	public static float density;
	private boolean isSupportsEs2 = false;
	
	public static int language = 0;

	@Override
	public void onCreate()
	{
		super.onCreate();
		mApplication = this;
		mContext = getApplicationContext();

		width = mContext.getResources().getDisplayMetrics().widthPixels;
		height = mContext.getResources().getDisplayMetrics().heightPixels;
		density = mContext.getResources().getDisplayMetrics().heightPixels;

		final ActivityManager activityManager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
		final ConfigurationInfo configurationInfo = activityManager.getDeviceConfigurationInfo();
		isSupportsEs2 = configurationInfo.reqGlEsVersion >= 0x20000 && Build.VERSION.SDK_INT >= 8;
		
		String country = getResources().getConfiguration().locale.getCountry();
		if (country.equalsIgnoreCase("CN"))
		{
			language = 0;
		}else if (country.equalsIgnoreCase("TW"))
		{
			language = 1;
		}else 
		{
			language = 2;
		}
		Util.checkPkg();
	}

	public static Context getContext()
	{
		return mContext;
	}

	public static APP getInstance()
	{
		return mApplication;
	}
	
	@Override
	public void onLowMemory()
	{
		new Thread(new Runnable()
		{
			@Override
			public void run()
			{
				System.gc();
			    System.runFinalization();
			}
		}).start();
		super.onLowMemory();
	}
	
}
