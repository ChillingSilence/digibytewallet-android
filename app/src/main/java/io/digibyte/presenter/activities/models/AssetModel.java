package io.digibyte.presenter.activities.models;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.MenuInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.view.ContextThemeWrapper;
import androidx.appcompat.widget.PopupMenu;
import androidx.databinding.BaseObservable;
import androidx.databinding.Bindable;
import androidx.databinding.BindingAdapter;

import java.util.LinkedList;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import io.digibyte.BR;
import io.digibyte.R;
import io.digibyte.databinding.AssetBinding;
import io.digibyte.presenter.activities.util.RetrofitManager;
import io.digibyte.presenter.adapter.DataBoundViewHolder;
import io.digibyte.presenter.adapter.DynamicBinding;
import io.digibyte.presenter.adapter.LayoutBinding;
import io.digibyte.presenter.fragments.FragmentNumberPicker;
import io.digibyte.presenter.interfaces.BRAuthCompletion;

public class AssetModel extends BaseObservable implements LayoutBinding, DynamicBinding {

    private AddressInfo.Asset asset;
    private MetaModel metaModel;
    private double assetAmount = 100.1;
    private static Handler handler = new Handler(Looper.getMainLooper());
    private static Executor executor = Executors.newSingleThreadExecutor();

    private static native String[] getNeededUTXO(int amount);

    public AssetModel(AddressInfo.Asset asset) {
        this.asset = asset;
    }

    @Override
    public int getLayoutId() {
        return R.layout.asset;
    }

    @Bindable
    public String getAssetImage() {
        if (metaModel == null) {
            return "";
        }
        return metaModel.metadataOfIssuence.data.urls[0].url;
    }

    @Bindable
    public String getAssetName() {
        if (metaModel == null) {
            return "";
        }
        return metaModel.metadataOfIssuence.data.assetName;
    }

    @Bindable
    public String getAssetQuantity() {
        if (metaModel == null) {
            return "";
        }
        if (asset.divisibility == 0) {
            return Double.toString(asset.amount);
        } else {
            return Double.toString((double) asset.amount / (Math.pow(10, asset.divisibility)));

        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssetModel that = (AssetModel) o;
        return Double.compare(that.assetAmount, assetAmount) == 0 &&
                Objects.equals(asset, that.asset) &&
                Objects.equals(metaModel, that.metaModel);
    }

    @Override
    public int hashCode() {
        return Objects.hash(asset, metaModel, assetAmount);
    }

    @Override
    public void bind(DataBoundViewHolder holder) {
        AssetBinding binding = (AssetBinding) holder.binding;
        binding.assetMenu.setOnClickListener(v -> {
            ContextThemeWrapper context = new ContextThemeWrapper(v.getContext(),
                    R.style.AssetPopup);
            showAssetMenu(context, v);
        });
        RetrofitManager.instance.getAssetMeta(asset.assetId, asset.assetUtxoTxId, asset.index,
                metaModel -> {
                    AssetModel.this.metaModel = metaModel;
                    notifyPropertyChanged(BR.assetName);
                    notifyPropertyChanged(BR.assetQuantity);
                    notifyPropertyChanged(BR.assetImage);
                });
    }

    private void showAssetMenu(Context context, View v) {
        PopupMenu popup = new PopupMenu(context, v);
        MenuInflater inflater = popup.getMenuInflater();
        inflater.inflate(R.menu.asset_menu, popup.getMenu());
        popup.setOnMenuItemClickListener(item -> {
            switch (item.getItemId()) {
                case R.id.send:
                    showSendMenu(context, v);
                    break;
            }
            return true;
        });
        popup.show();
    }

    private void showSendMenu(Context context, View v) {
        PopupMenu popup = new PopupMenu(context, v);
        MenuInflater inflater = popup.getMenuInflater();
        inflater.inflate(R.menu.send_asset_menu, popup.getMenu());
        popup.setOnMenuItemClickListener(item -> {
            switch (item.getItemId()) {
                case R.id.qr:
                    break;
                case R.id.paste:
                    ClipboardManager clipboard = (ClipboardManager) context.getSystemService(
                            Context.CLIPBOARD_SERVICE);
                    ClipData clipData = clipboard.getPrimaryClip();
                    if (clipData != null && clipData.getItemCount() > 0) {
                        CharSequence address = clipData.getItemAt(0).getText();
                        try {
                            Log.d(AssetModel.class.getSimpleName(), "Clipped Address: " + address);
                            Log.d(AssetModel.class.getSimpleName(),
                                    "Asset UTXO Addr: " + asset.utxoAddress);

                            SendAsset sendAsset = new SendAsset(
                                    Integer.toString(500),
                                    asset.utxoAddress,
                                    trimNullEmpty(getNeededUTXO(500)),
                                    address.toString(),
                                    metaModel.assetId
                            );
                            FragmentNumberPicker.show(
                                    (AppCompatActivity) v.getContext(),
                                    new BRAuthCompletion.AuthType(sendAsset)
                            );
                        } catch (Throwable t) {
                            t.printStackTrace();
                        }
                    } else {
                        Toast.makeText(context, R.string.NoClipData, Toast.LENGTH_SHORT).show();
                    }
                    break;
            }
            return true;
        });
        popup.show();
    }

    private String[] trimNullEmpty(String[] values) {
        LinkedList<String> newValues = new LinkedList<>();
        for (String value : values) {
            if (!TextUtils.isEmpty(value) && !value.toLowerCase().equals("null")) {
                newValues.add(value);
            }
        }
        String[] sNewValues = new String[newValues.size()];
        return newValues.toArray(sNewValues);
    }

    @BindingAdapter("remoteImage")
    public static void remoteImage(ImageView imageView, String imageData) {
        if (TextUtils.isEmpty(imageData)) {
            return;
        }
        executor.execute(() -> {
            byte[] image = Base64.decode(imageData.substring(imageData.indexOf(",")),
                    Base64.DEFAULT);
            Bitmap bitmap = BitmapFactory.decodeByteArray(image, 0, image.length);
            handler.post(() -> imageView.setImageBitmap(bitmap));
        });
    }
}