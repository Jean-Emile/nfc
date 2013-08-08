Mifare Classic 1K API
--

###Requirements

1. Create a new Android project. Paste the packages `org.kevoree.android.nfc.api` and  `org.kevoree.android.nfc.impl` in your `src` folder.
  
2. Create `nfc_tech_filter.xml` in `<project-root>/res/xml` and paste :   
```xml
<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
    <tech-list> 
        <tech>android.nfc.tech.NfcA</tech> 
        <tech>android.nfc.tech.MifareClassic</tech> 
    </tech-list>
</resources> 
``` 
 
3. Add `<uses-permission>` in `AndroidManifest.xml` to access the NFC hardware  
```xml
    <uses-permission android:name="android.permission.NFC" />  
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```    
4. Add `<intent-filter>` in `AndroidManifest.xml`  
```xml
<intent-filter>  
<action android:name="android.nfc.action.TECH_DISCOVERED" />  
</intent-filter>  
```  

5. Add `<meta-data>` in `AndroidManifest.xml`  
```xml
 <meta-data android:name="android.nfc.action.TECH_DISCOVERED"  
android:resource="@xml/nfc_tech_filter" />
```    

6. Add `<uses-feature>` in `AndroidManifest.xml`  
```xml
<uses-feature android:name="android.hardware.nfc" android:required="true" />
```

###Creation of MainActivity


#### Create field :
```java
  private NFC_Mifare_classic puceNFC; 
  private NfcAdapter mAdapter; 
  private PendingIntent mPendingIntent; 
  private IntentFilter[] mFilters; 
  private String[][] mTechLists; 
```
####onCreate :
```java  
// Check for available NFC Adapter  
mAdapter = NfcAdapter.getDefaultAdapter(this);  
// Create a generic PendingIntent that will be deliver to this activity.  
mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);  
// Setup an intent filter for all MIME based dispatches   
IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);  
try {  
ndef.addDataType("*/*");  
} catch (MalformedMimeTypeException e) {  
throw new RuntimeException("fail", e);  
}  
mFilters = new IntentFilter[] { ndef, };  
// Setup a tech list for all MifareClassic tags
mTechLists = new String[][] { new String[] { MifareClassic.class.getName() } };  
//Get intent  
Intent intent = getIntent();  
//Treat Intent  
onNewIntent(intent);  
```

####onResume : 
```java
@Override 
public void onResume() { 
  super.onResume(); 
  // Register the foreground Activity for tag reading events
  mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters, mTechLists); 
}
```

####onPause :
```java
@Override 
public void onPause(){ 
  super.onPause(); 
  // Unregister the foreground Activity for tag reading events 
  mAdapter.disableForegroundDispatch(this); 
} 
```

####onNewIntent :
```java
@Override
public void onNewIntent(Intent intent) { 
  //this method gets called when the user attaches a Tag to the device. 
  //Create new NFC_Mifare_Classic 
  puceNFC = new NFC_Mifare_classic();  
  //Check to see that the Activity started due to an Android Beam 
  puceNFC.treatAsNewTag(intent);  
  Toast.makeText(getApplicationContext(), "UID ::: " +puceNFC.getId(),   Toast.LENGTH_LONG).show(); 
} 
```


  
