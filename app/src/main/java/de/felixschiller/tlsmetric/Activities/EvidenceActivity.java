package de.felixschiller.tlsmetric.Activities;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.TaskStackBuilder;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v4.app.NotificationCompat;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;

import de.felixschiller.tlsmetric.Assistant.Const;
import de.felixschiller.tlsmetric.Assistant.ContextSingleton;
import de.felixschiller.tlsmetric.PacketAnalyze.Announcement;
import de.felixschiller.tlsmetric.PacketAnalyze.Evidence;
import de.felixschiller.tlsmetric.PacketAnalyze.PackageInformation;
import de.felixschiller.tlsmetric.R;

public class EvidenceActivity extends AppCompatActivity{
    private boolean onDetailPage;
    NotificationCompat.Builder mBuilder =
            new NotificationCompat.Builder(this)
                    .setSmallIcon(R.drawable.icon)
                    .setContentTitle("TLSMetric")
                    .setContentText( Evidence.newWarnings + " new warnings encountered.");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evidence);
        ContextSingleton.setContext(this);
        onDetailPage = false;

        //Toolbar
        Toolbar toolbar = (Toolbar) findViewById(R.id.evidence_toolbar);
        setSupportActionBar(toolbar);
        toolbar.setLogo(R.drawable.icon);
        toolbar.setLogoDescription(R.string.app_name);

        //Notification builder


        //EvidenceList
        final ListView listview = (ListView) findViewById(android.R.id.list);

        final EvidenceAdapter adapter;
        if(Evidence.mEvidence != null){
            adapter = new EvidenceAdapter(this, Evidence.getSortedEvidence());
        } else {
            if(Const.IS_DEBUG) Log.e(Const.LOG_TAG, "Evidence list not existing or empty!");
            adapter = new EvidenceAdapter(this, new ArrayList<Announcement>());
        }

        listview.setAdapter(adapter);

        listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, final View view,
                                    int position, long id) {
                final Announcement ann = (Announcement) parent.getItemAtPosition(position);
                view.animate().setDuration(500).alpha((float)0.5)
                        .withEndAction(new Runnable() {
                            @Override
                            public void run() {
                                if (ann.filter.severity != -1) {
                                    onDetailPage = true;
                                    EvidenceAdapter newAdapter = new EvidenceAdapter(getApplicationContext(), Evidence.getSortedEvidenceDetail(ann.srcPort));
                                    listview.setAdapter(newAdapter);
                                } else {
                                    Toast toast = Toast.makeText(ContextSingleton.getContext(), "No detail availiable for this connection", Toast.LENGTH_LONG);
                                    toast.show();
                                }
                            }
                        });
            }

        });
    }




    private class EvidenceAdapter extends ArrayAdapter<Announcement> {

        private final Announcement[] anns;
        private final Context context;

        public EvidenceAdapter(Context context, ArrayList<Announcement> AnnList) {
            super(context, R.layout.evidence_list_entry, AnnList);
            this.context = context;
            this.anns = new Announcement[AnnList.size()];
            for(int i = 0; i < AnnList.size(); i++){
                this.anns[i] = AnnList.get(i);
            }
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);

            View rowView = inflater.inflate(R.layout.evidence_list_entry, parent, false);

            PackageInformation pi = Evidence.getPackageInformation(anns[position].pid);
            //First Line Text
            TextView firstLine = (TextView) rowView.findViewById(R.id.firstLine);
            String first = pi.packageName;
            firstLine.setText(first);

            //second Line Text
            TextView secondLine = (TextView) rowView.findViewById(R.id.secondLine);
            String second = "Host: " + anns[position].url;
            secondLine.setText(second);

            //App icon
            ImageView imageView = (ImageView) rowView.findViewById(R.id.icon);
            imageView.setImageDrawable(pi.icon);

            //Status icon
            ImageView imageStatusView = (ImageView) rowView.findViewById(R.id.statusIcon);
            int severity = anns[position].filter.severity;
            if(severity == 3){
                imageStatusView.setImageResource(R.drawable.icon_warn_red);
            } else if (severity == 2){
                imageStatusView.setImageResource(R.drawable.icon_warn_yell);
            } else if (severity == 1) {
                imageStatusView.setImageResource(R.drawable.icon_warn_yell);
            } else if (severity == 0){
                imageStatusView.setImageResource(R.drawable.icon_ok);
            } else if (severity == -1) {
                imageStatusView.setImageResource(R.drawable.icon_quest);
            }

            //Status Text
            TextView statusLine = (TextView) rowView.findViewById(R.id.statusLine);
            String status = "Level :" + severity;
            statusLine.setText(status);
            return rowView;
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_tlsmetric, menu);
        return true;
    }

    //menu
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.action_settings:
                return true;

            case R.id.action_back:
                if(onDetailPage){
                    ListView listview = (ListView) findViewById(android.R.id.list);
                    EvidenceAdapter adapter = new EvidenceAdapter(ContextSingleton.getContext(), Evidence.mEvidence);
                    listview.setAdapter(adapter);
                    adapter.notifyDataSetChanged();
                    onDetailPage = false;
                } else{
                    Intent intent = new Intent(ContextSingleton.getContext(), MainActivity.class);
                    startActivity(intent);
                }

                return true;

            case R.id.action_refresh:
                Evidence.disposeInactiveEvidence();

                if(onDetailPage){
                    onDetailPage = false;
                }
                ListView listview = (ListView) findViewById(android.R.id.list);
                EvidenceAdapter adapter = new EvidenceAdapter(ContextSingleton.getContext(), Evidence.mEvidence);
                listview.setAdapter(adapter);
                adapter.notifyDataSetChanged();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void showNotification(){

        // Creates an explicit intent for an Activity in your app
        Intent resultIntent = new Intent(this, EvidenceActivity.class);

        // The stack builder object will contain an artificial back stack for the
        // started Activity.
        // This ensures that navigating backward from the Activity leads out of
        // your application to the Home screen.
        TaskStackBuilder stackBuilder = TaskStackBuilder.create(this);

        // Adds the back stack for the Intent (but not the Intent itself)
        stackBuilder.addParentStack(EvidenceActivity.class);

        // Adds the Intent that starts the Activity to the top of the stack
        stackBuilder.addNextIntent(resultIntent);
        PendingIntent resultPendingIntent =
                stackBuilder.getPendingIntent(0, PendingIntent.FLAG_UPDATE_CURRENT);
        mBuilder.setContentIntent(resultPendingIntent);
        NotificationManager mNotificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        // mId allows you to update the notification later on.
        mNotificationManager.notify(Const.LOG_TAG, 1, mBuilder.build());
    }58

    @Override
    public void onDestroy(){
        super.onDestroy();
    }


}