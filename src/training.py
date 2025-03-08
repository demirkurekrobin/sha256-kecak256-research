import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, optimizers, mixed_precision
from tensorflow.keras.callbacks import EarlyStopping
import os
import sha256_extension

os.environ["TF_MPS_ENABLE"] = "1"
os.environ["TF_NUM_INTEROP_THREADS"] = "8"
os.environ["TF_NUM_INTRAOP_THREADS"] = "8"

mixed_precision.set_global_policy('mixed_bfloat16')
#tf.config.experimental.set_memory_growth(tf.config.list_physical_devices('GPU')[0], True)

sha256_extension.call_init()

print("🔄 Lade initiale Daten...")
X_full, y_full = sha256_extension.call_nextData()
y_full = ((y_full // 8) - 1).astype(np.int32)

split_index = int(len(X_full) * 0.9)
X_train, X_val = X_full[:split_index], X_full[split_index:]
y_train, y_val = y_full[:split_index], y_full[split_index:]

lr_schedule = tf.keras.optimizers.schedules.CosineDecayRestarts(
    initial_learning_rate=1.179e-05*10,
    first_decay_steps=12000,
    t_mul=4.0,
    m_mul=0.7,
    alpha=0.000164
)

optimizer = optimizers.Adam(learning_rate=lr_schedule)

def residual_block(x, units):
    shortcut = x

    x = layers.Dense(units, activation='relu')(x)
    x = layers.LayerNormalization(center=False, scale=False)(x)
    x = layers.Dense(units, activation=None)(x)

    gate = layers.Dense(units, activation='sigmoid')(x)
    x = layers.Multiply()([x, gate])

    shortcut = layers.Dense(units, activation=None)(shortcut)

    x = layers.Add()([x, shortcut])
    return layers.ReLU()(x)



inputs = tf.keras.Input(shape=(X_full.shape[1],))
x = layers.Dense(1024, kernel_initializer='he_normal')(inputs)
x = layers.LayerNormalization(center=False, scale=False)(x)
x = layers.LeakyReLU(negative_slope=0.1)(x)
x = residual_block(x, 768)
x = layers.LayerNormalization(center=False, scale=False)(x)

#x = layers.Reshape((1, -1))(x)

# MultiHeadAttention-Schicht
#transformer_layer = layers.MultiHeadAttention(num_heads=8, key_dim=64)(x, x)

# Residual Connection + Layer Normalization
#x = layers.Add()([x, transformer_layer])
#x = layers.LayerNormalization()(x)

# Optional: Zurück zu (batch_size, features) bringen
#x = layers.Flatten()(x)


#x = residual_block(x, 512)
#x = layers.Reshape((1, 768))(x)
#x = layers.LSTM(512, return_sequences=True)(x) 
#x = layers.LSTM(256, return_sequences=False)(x)
x = residual_block(x, 512)
#x = layers.Dense(512, kernel_initializer='he_normal')(x)
#x = layers.LeakyReLU(negative_slope=0.1)(x)
x = residual_block(x, 384)
x = residual_block(x, 256)

x = layers.Dense(55, activation='softmax')(x)
outputs = layers.Softmax()(x / 2.0)

model = tf.keras.Model(inputs, outputs)

model.compile(optimizer=optimizer, loss='sparse_categorical_crossentropy', metrics=['accuracy'])
early_stopping = EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True)

epochs = 300
batch_size = 1024

print("Starte Training – 1 Mio. neue Daten pro Epoche werden direkt aus dem C-Puffer geladen...")

for epoch in range(epochs):
    print(f"🔄 Epoche {epoch+1}/{epochs}")

    train_dataset = tf.data.Dataset.from_tensor_slices((X_train, y_train)) \
        .batch(batch_size) \
        .prefetch(tf.data.AUTOTUNE)

    val_dataset = tf.data.Dataset.from_tensor_slices((X_val, y_val)) \
        .batch(batch_size) \
        .prefetch(tf.data.AUTOTUNE)

    history = model.fit(train_dataset, validation_data=val_dataset, epochs=1, callbacks=[early_stopping])

    print("Lade neue Daten...")
    X_full, y_full = sha256_extension.call_nextData()
    y_full = ((y_full // 8) - 1).astype(np.int32)

    split_index = int(len(X_full) * 0.9)
    X_train, X_val = X_full[:split_index], X_full[split_index:]
    y_train, y_val = y_full[:split_index], y_full[split_index:]

model.save("sha256_model_transformer.keras")
print(" Modell gespeichert als 'sha256_model_transformer.keras'")
sha256_extension.call_shutdown()
