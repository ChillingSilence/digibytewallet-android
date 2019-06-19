package io.digibyte.tools.database;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.Query;

import java.util.List;

@Dao
public interface AssetNameDao {

    @Query("SELECT * FROM asset_names")
    List<AssetName> getAll();

    @Query("SELECT * FROM asset_names WHERE hash LIKE :hash LIMIT 1")
    AssetName FindAssetNameFromHash(String hash);

    @Insert
    void insertAll(AssetName... assetNames);
}