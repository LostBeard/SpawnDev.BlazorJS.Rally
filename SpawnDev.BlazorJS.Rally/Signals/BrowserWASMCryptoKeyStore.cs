using SpawnDev.BlazorJS.JSObjects;

namespace SpawnDev.BlazorJS.Rally.Signals
{
    /// <summary>
    /// A simple IndexedDB based CryptoKey store for Browser WASM applications<br/>
    /// Allows storing and retrieving CryptoKeyPairs by string name even if created with exportable set to false as<br/>
    /// keys do not need to be exported to be stored in IndexedDB<br/>
    /// This allows for more secure key storage in the browser<br/>
    /// </summary>
    public class BrowserWASMCryptoKeyStore
    {
        /// <summary>
        /// The database name used for storage<br/>
        /// </summary>
        public string DBName { get; private set; }
        /// <summary>
        /// The object store name used for storage<br/>
        /// </summary>
        public string StoreName { get; private set; }
        /// <summary>
        /// Creates a new BrowserWASMCryptoKeyStore instance<br/>
        /// </summary>
        /// <param name="dbName"></param>
        /// <param name="storeName"></param>
        public BrowserWASMCryptoKeyStore(string? dbName = null, string? storeName = null)
        {
            DBName = string.IsNullOrEmpty(dbName) ? nameof(BrowserWASMCryptoKeyStore) : dbName;
            StoreName = string.IsNullOrEmpty(storeName) ? nameof(BrowserWASMCryptoKeyStore) : storeName;
        }
        /// <summary>
        /// Gets the IndexedDB database instance<br/>
        /// </summary>
        /// <returns></returns>
        async Task<IDBDatabase> GetDB()
        {
            using var idbFactory = new IDBFactory();
            var idb = await idbFactory.OpenAsync(DBName, 1, (evt) =>
            {
                // upgrade needed
                using var request = evt.Target;
                using var db = request.Result;
                var stores = db.ObjectStoreNames;
                if (!stores.Contains(StoreName))
                {
                    using var myKeysStore = db.CreateObjectStore<string, CryptoKeyPair>(StoreName);
                }
            });
            return idb;
        }
        /// <summary>
        /// Returns true if the key store database exists<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<bool> DBExists()
        {
            using var idbFactory = new IDBFactory();
            var databases = await idbFactory.Databases();
            return databases.Any(db => db.Name == DBName);
        }
        /// <summary>
        /// Returns true if the key store and database exists<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<bool> Exists()
        {
            using var idbFactory = new IDBFactory();
            var databases = await idbFactory.Databases();
            var dbExists = databases.Any(db => db.Name == DBName);
            if (!dbExists) return false;
            using var idb = await idbFactory.OpenAsync(DBName);
            return idb.ObjectStoreNames.Contains(StoreName);
        }
        /// <summary>
        /// Returns true if a key with the given name exists<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<bool> Exists(string name)
        {
            var storeExists = await Exists();
            if (!storeExists) return false;
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var namesArray = await objectStore.GetAllKeysAsync();
            var names = namesArray.ToArray();
            return names.Contains(name);
        }
        /// <summary>
        /// Clears the key store<br/>
        /// </summary>
        /// <returns></returns>
        public async Task Clear()
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.ClearAsync();
        }
        /// <summary>
        /// Gets a CryptoKeyPair by name or null if not found<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<CryptoKeyPair?> Get(string name)
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var keys = await objectStore.GetAsync(name);
            return keys;
        }
        /// <summary>
        /// Sets a CryptoKeyPair by name<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        public async Task Set(string name, CryptoKeyPair keys)
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, true);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.PutAsync(keys, name);
        }
        /// <summary>
        /// Removes a CryptoKeyPair by name<br/>
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task Remove(string name)
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, true);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            await objectStore.DeleteAsync(name);
        }
        /// <summary>
        /// Lists all stored key names<br/>
        /// </summary>
        /// <returns></returns>
        public async Task<string[]> List()
        {
            using var idb = await GetDB();
            using var tx = idb.Transaction(StoreName, false);
            using var objectStore = tx.ObjectStore<string, CryptoKeyPair>(StoreName);
            var keysArray = await objectStore.GetAllKeysAsync();
            var keys = keysArray.ToArray();
            return keys;
        }
    }
}

