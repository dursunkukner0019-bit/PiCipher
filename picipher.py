import streamlit as st
from picipher import encrypt, decrypt


st.set_page_config(
    page_title="PiCipher",
    page_icon="🔐",
    layout="centered",
)


st.title("🔐 PiCipher")
st.subheader("π tabanlı güvenli metin şifreleme")

st.info(
    "Metninizi şifreleyin ve şifreli metni karşı tarafa "
    "anahtarınızla birlikte güvenli şekilde iletin."
)


st.markdown("### 🔑 Anahtar")

password = st.text_input(
    "Şifreleme anahtarı",
    type="password",
    placeholder="Örneğin: 1 veya güçlü bir parola",
)


tab1, tab2 = st.tabs(
    ["🔒 Şifrele", "🔓 Şifre Çöz"]
)


with tab1:

    st.markdown("### 📝 Metin")

    text = st.text_area(
        "Şifrelenecek metni yazın",
        height=220,
        placeholder="Mesajınızı buraya yazın...",
        key="encrypt_text",
    )

    if st.button(
        "🔒 METNİ ŞİFRELE",
        use_container_width=True,
    ):

        if not password:
            st.error("Lütfen bir anahtar girin.")

        elif not text:
            st.error("Lütfen şifrelenecek metni girin.")

        else:

            try:

                encrypted = encrypt(
                    text,
                    password,
                )

                st.success(
                    "Metin başarıyla şifrelendi."
                )

                st.markdown("### 📦 Şifreli metin")

                st.code(
                    encrypted,
                    language="text",
                )

                st.download_button(
                    "⬇️ Şifreli metni kaydet",
                    encrypted,
                    file_name="picipher.txt",
                    mime="text/plain",
                    use_container_width=True,
                )

            except Exception as error:

                st.error(
                    f"Şifreleme hatası: {error}"
                )


with tab2:

    st.markdown("### 📦 Şifreli metin")

    encrypted_text = st.text_area(
        "Şifreli metni buraya yapıştırın",
        height=220,
        placeholder="PiCipher şifreli metni buraya yapıştırın...",
        key="decrypt_text",
    )

    if st.button(
        "🔓 ŞİFREYİ ÇÖZ",
        use_container_width=True,
    ):

        if not password:
            st.error("Lütfen anahtarı girin.")

        elif not encrypted_text:
            st.error("Lütfen şifreli metni girin.")

        else:

            try:

                decrypted = decrypt(
                    encrypted_text.strip(),
                    password,
                )

                st.success(
                    "Şifre başarıyla çözüldü."
                )

                st.markdown("### 📝 Çözülmüş metin")

                st.text_area(
                    "Sonuç",
                    decrypted,
                    height=220,
                    key="result_text",
                )

            except ValueError:

                st.error(
                    "❌ Anahtar yanlış veya şifreli veri değiştirilmiş."
                )

            except Exception as error:

                st.error(
                    f"Çözme hatası: {error}"
                )


st.divider()

st.caption(
    "PiCipher • AES-256-GCM • Scrypt • π tabanlı katman"
)
