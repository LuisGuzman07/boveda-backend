import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.auth import Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.assistant import (
    AssistantAction,
    AssistantCategory,
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantTopic,
    AssistantTopicsResponse,
)

logger = logging.getLogger(__name__)


def _normalize_text(text: str) -> str:
    """Elimina acentos, pasa a minúsculas y remueve caracteres especiales repetidos."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("utf-8")
    return text.lower().strip()


class AssistantService:
    """
    Agente Asistente Inteligente de Bóveda Híbrida.
    Proporciona respuestas interactivas, explicaciones paso a paso de todas las funciones
    del software, atajos de acción directos a páginas y modales, y registro de auditoría.
    """

    def __init__(self, db: Session):
        self.db = db
        self.auth_repo = AuthRepository(db)

    def get_topics(self) -> AssistantTopicsResponse:
        """Retorna los tópicos y guías rápidas principales organizadas por categoría."""
        topics = [
            AssistantTopic(
                id="vault_creation_and_files",
                title="Bóvedas y Cifrado de Archivos (CU-06 / CU-08 / CU-10)",
                description="Aprende a crear bóvedas, desbloquearlas localmente y cifrar/descifrar archivos de forma segura.",
                category="BOVEDAS",
                sample_queries=[
                    "¿Cómo creo una nueva bóveda?",
                    "¿Cómo desbloqueo mi bóveda con la contraseña maestra?",
                    "¿Cómo subo y cifro un archivo en la bóveda?",
                    "¿Cómo descargo y descifro un archivo?",
                ],
                icon="Lock",
            ),
            AssistantTopic(
                id="trusted_devices",
                title="Dispositivos de Confianza (CU-04 / CU-05)",
                description="Cómo autorizar tu equipo actual mediante el desafío criptográfico Ed25519 y gestionar terminales.",
                category="DISPOSITIVOS",
                sample_queries=[
                    "¿Cómo autorizo mi equipo como dispositivo de confianza?",
                    "¿Por qué sale 'La autorización directa fue retirada'?",
                    "¿Cómo revoco la confianza de un dispositivo?",
                    "¿Puedo autorizar mi teléfono desde la computadora?",
                ],
                icon="Laptop",
            ),
            AssistantTopic(
                id="emergency_recovery",
                title="Recuperación de Emergencia (CU-12)",
                description="Genera y utiliza kits de recuperación con claves envueltas para casos de olvido de contraseña.",
                category="RECUPERACION",
                sample_queries=[
                    "¿Cómo genero el kit de recuperación de emergencia?",
                    "¿Cómo recupero mi bóveda si olvidé la contraseña maestra?",
                    "¿Qué contiene el kit de recuperación?",
                ],
                icon="LifeBuoy",
            ),
            AssistantTopic(
                id="vault_sharing",
                title="Compartición y Delegación de Bóvedas (CU-17)",
                description="Comparte el acceso a tus bóvedas con miembros del equipo sin exponer tus claves privadas.",
                category="COMPARTICION",
                sample_queries=[
                    "¿Cómo comparto una bóveda con otro usuario?",
                    "¿Qué permisos y roles existen para compartir?",
                    "¿Cómo se asegura el Conocimiento Cero al compartir?",
                ],
                icon="Share2",
            ),
            AssistantTopic(
                id="audit_and_ai_anomalies",
                title="Auditoría e IA Local de Anomalías (CU-20 / CU-22)",
                description="Consulta la bitácora inmutable con hash chaining y ejecuta el modelo local de detección de anomalías.",
                category="AUDITORIA_IA",
                sample_queries=[
                    "¿Cómo veo los registros de auditoría?",
                    "¿Cómo funciona la IA de detección de anomalías?",
                    "¿Qué significa un riesgo CRÍTICO o ALTO en una anomalía?",
                ],
                icon="Brain",
            ),
            AssistantTopic(
                id="security_and_mfa",
                title="Seguridad, Doble Factor (MFA) y Políticas",
                description="Activa el autenticador TOTP (Google Authenticator) y gestiona los tiempos de bloqueo de sesión.",
                category="SEGURIDAD_MFA",
                sample_queries=[
                    "¿Cómo activo el doble factor de autenticación (MFA)?",
                    "¿Cómo funciona el bloqueo automático por inactividad?",
                    "¿Cuáles son los requisitos de las contraseñas?",
                ],
                icon="ShieldCheck",
            ),
        ]

        categories = [
            {"id": "BOVEDAS", "name": "Bóvedas y Cifrado", "icon": "Lock"},
            {"id": "DISPOSITIVOS", "name": "Dispositivos de Confianza", "icon": "Laptop"},
            {"id": "RECUPERACION", "name": "Kit de Emergencia (CU-12)", "icon": "LifeBuoy"},
            {"id": "COMPARTICION", "name": "Compartición de Bóvedas (CU-17)", "icon": "Share2"},
            {"id": "AUDITORIA_IA", "name": "Auditoría e IA de Anomalías (CU-22)", "icon": "Brain"},
            {"id": "SEGURIDAD_MFA", "name": "MFA y Políticas de Seguridad", "icon": "ShieldCheck"},
            {"id": "GENERAL", "name": "General y Ayuda", "icon": "HelpCircle"},
        ]

        return AssistantTopicsResponse(topics=topics, categories=categories)

    def process_chat(
        self,
        request: AssistantChatRequest,
        user: Optional[Usuario] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AssistantChatResponse:
        """
        Procesa el mensaje del usuario, determina la intención mediante el motor semántico
        local, formula una respuesta paso a paso con acciones interactivas y registra auditoría.
        """
        raw_msg = request.message.strip()
        norm = _normalize_text(raw_msg)

        # Registro auditable de la consulta al asistente (CU-20)
        category, response_md, actions, follow_ups = self._resolve_intent(norm, raw_msg, user, request.current_path)

        if user:
            try:
                self.auth_repo.create_audit_event(
                    accion="ASISTENTE_IA_CONSULTA",
                    tipo_evento="USUARIO",
                    resultado="EXITO",
                    user_id=user.id_usuario,
                    ip=client_ip,
                    user_agent=user_agent,
                    detalles={
                        "categoria": category,
                        "longitud_pregunta": len(raw_msg),
                        "ruta_origen": request.current_path,
                    },
                )
            except Exception as e:
                logger.warning(f"No se pudo auditar la consulta del asistente: {e}")

        return AssistantChatResponse(
            message=response_md,
            category=category,
            suggested_actions=actions,
            suggested_questions=follow_ups,
        )

    def _resolve_intent(
        self,
        norm: str,
        raw: str,
        user: Optional[Usuario],
        current_path: Optional[str],
    ) -> Tuple[AssistantCategory, str, List[AssistantAction], List[str]]:
        """Motor de reconocimiento semántico de intenciones y generación de procedimientos."""

        # -------------------------------------------------------------
        # 1. DISPOSITIVOS DE CONFIANZA / CU-04 / CU-05 / DESAFIO CRIPTOGRAFICO
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "dispositivo", "confianza", "confiable", "desafio criptografico",
            "autorizacion directa", "cu05", "cu-05", "cu04", "cu-04", "ed25519",
            "retirada", "revocar dispositivo", "hardware", "terminal", "posesion"
        ]):
            if any(w in norm for w in ["retirada", "por que", "error", "falla", "directa"]):
                msg = (
                    "### 🛡️ ¿Por qué se retiró la autorización directa de dispositivos?\n\n"
                    "Bajo la arquitectura de **Confianza Cero (Zero-Trust)** y **Conocimiento Cero (Zero-Knowledge)** de Bóveda Híbrida:\n\n"
                    "1. **Seguridad contra secuestro de sesión:** Si un dispositivo pudiera autorizarse con un simple clic REST directo, "
                    "cualquier atacante que intercepte un token de sesión podría marcar como 'confiable' cualquier hardware falso sin tener acceso físico a él.\n"
                    "2. **Prueba de Posesión (Proof of Possession):** Ahora cada dispositivo debe demostrar matemáticamente que posee la clave privada "
                    "**Ed25519** generada localmente en su hardware (`TweetNaCl`), firmando un desafío canónico criptográfico (`DEVICE_ENROLLMENT`).\n\n"
                    "**👉 ¿Cómo autorizar tu equipo actual?**\n"
                    "Simplemente abre el modal de **Dispositivos de Confianza** y haz clic en **'Autorizar como Confiable'**. "
                    "Tu navegador firmará automáticamente el desafío criptográfico y quedará verificado al instante."
                )
            else:
                msg = (
                    "### 💻 Cómo gestionar y autorizar tus Dispositivos de Confianza (CU-04 / CU-05)\n\n"
                    "Para vincular tu equipo actual de forma segura:\n\n"
                    "1. **Abre el modal de Dispositivos:** Ve al **Panel Principal** y haz clic en el botón **'Dispositivos de Confianza'**.\n"
                    "2. **Autoriza el equipo actual:** En la lista, localiza la tarjeta que tiene la etiqueta `Este Dispositivo (Actual)` "
                    "y pulsa **'Autorizar como Confiable'**.\n"
                    "3. **Firma Criptográfica Automática:** Tu navegador construirá el transcript canónico `boveda-device-challenge-v1`, "
                    "lo firmará con su clave privada Ed25519 local y enviará la prueba al servidor para marcarlo como `TRUSTED`.\n"
                    "4. **Dispositivos Remotos:** Por seguridad estricta, no puedes autorizar un teléfono u otra computadora desde esta ventana. "
                    "Debes iniciar sesión físicamente en ese otro equipo para que su hardware firme su propio desafío.\n"
                    "5. **Revocar confianza:** Puedes hacer clic en **'Revocar Confianza'** o **'Desvincular'** en cualquier momento para expulsar un equipo."
                )

            actions = [
                AssistantAction(
                    label="Abrir Dispositivos de Confianza",
                    action_type="modal",
                    target="trusted_devices",
                    icon="Laptop",
                ),
                AssistantAction(
                    label="Ir al Panel",
                    action_type="navigate",
                    target="/dashboard",
                    icon="LayoutDashboard",
                ),
            ]
            follow_ups = [
                "¿Por qué sale el mensaje de que la autorización directa fue retirada?",
                "¿Cómo revoco la confianza de un dispositivo perdido?",
                "¿Cómo se asegura el sistema de que las claves nunca salgan de mi equipo?",
            ]
            return "DISPOSITIVOS", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 2. BÓVEDAS & CIFRADO DE ARCHIVOS (CU-06 / CU-08 / CU-10)
        # -------------------------------------------------------------
        # -------------------------------------------------------------
        # 2. RECUPERACIÓN DE EMERGENCIA (CU-12)
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "emergencia", "kit", "recuperacion", "recuperar", "olvide",
            "perdi", "cu12", "cu-12", "rescate"
        ]):
            msg = (
                "### 🆘 Kit de Recuperación de Emergencia (CU-12)\n\n"
                "El Kit de Emergencia es tu seguro de vida para no perder el acceso a tus archivos si olvidas la contraseña maestra o pierdes tu dispositivo:\n\n"
                "1. **Cómo generar el Kit:**\n"
                "   - Ve a la sección **Bóvedas**.\n"
                "   - En la tarjeta de la bóveda deseada, haz clic en **'Kit de Emergencia'**.\n"
                "   - Se generará un paquete criptográfico seguro con una clave de recuperación envuelta y un documento con instrucciones imprimibles y códigos de seguridad.\n"
                "2. **Guarda el Kit en un lugar seguro:**\n"
                "   - Descárgalo y almacénalo fuera de línea (ej. en una memoria USB cifrada o en papel en una caja fuerte).\n"
                "3. **Cómo usarlo para restaurar acceso:**\n"
                "   - Si no puedes ingresar a la bóveda, selecciona la opción **'Recuperar Bóveda'**, carga tu kit de emergencia e introduce tu código de rescate.\n"
                "   - Esto desenvuelve la clave de la bóveda y te permite reasignar una nueva contraseña maestra sin pérdida de datos."
            )
            actions = [
                AssistantAction(
                    label="Ver mis Bóvedas",
                    action_type="navigate",
                    target="/vaults",
                    icon="Lock",
                ),
                AssistantAction(
                    label="Ir al Panel",
                    action_type="navigate",
                    target="/dashboard",
                    icon="LayoutDashboard",
                ),
            ]
            follow_ups = [
                "¿El servidor puede ver mi clave de recuperación?",
                "¿Puedo generar múltiples kits de emergencia?",
                "¿Cómo comparto la bóveda con otro usuario?",
            ]
            return "RECUPERACION", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 3. COMPARTICIÓN Y DELEGACIÓN DE ACCESOS (CU-17)
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "compartir", "comparto", "comparticion", "delegar", "delegacion", "miembro", "equipo",
            "permiso", "rol", "acceso", "lectura", "escritura", "cu17", "cu-17", "invitar"
        ]):
            msg = (
                "### 👥 Compartición Segura de Bóvedas (CU-17)\n\n"
                "Bóveda Híbrida permite compartir archivos y bóvedas completas preservando el **Conocimiento Cero**:\n\n"
                "1. **Abre tu Bóveda:** En la sección **Bóvedas**, busca la bóveda que deseas compartir y pulsa **'Compartir Acceso'**.\n"
                "2. **Indica el destinatario:** Escribe el correo electrónico del usuario registrado con quien deseas compartir.\n"
                "3. **Elige el nivel de permisos:**\n"
                "   - 👁️ **LECTURA:** El destinatario puede consultar y descargar archivos descifrándolos, pero no subir ni eliminar.\n"
                "   - ✏️ **ESCRITURA:** Puede subir nuevos archivos cifrados y consultar los existentes.\n"
                "   - 👑 **ADMIN:** Puede gestionar miembros, permisos y modificar la bóveda.\n"
                "4. **Envoltura Criptográfica:** Tu navegador descarga la clave pública registrada del destinatario y envuelve la clave de la bóveda específicamente para él. "
                "El servidor solo almacena el sobre cifrado y nunca ve la clave."
            )
            actions = [
                AssistantAction(
                    label="Ir a Bóvedas para Compartir",
                    action_type="navigate",
                    target="/vaults",
                    icon="Share2",
                ),
            ]
            follow_ups = [
                "¿Cómo revoco el acceso a un usuario compartido?",
                "¿Cómo sé si el destinatario tiene un dispositivo confiable registrado?",
                "¿Cómo veo los registros de auditoría de las descargas?",
            ]
            return "COMPARTICION", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 4. AUDITORÍA E IA LOCAL DE ANOMALÍAS (CU-20 / CU-22)
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "auditoria", "anomalia", "anomalias", "ia local", "isolation forest",
            "bitacora", "eventos", "hash", "cadena", "cu20", "cu-20", "cu22",
            "cu-22", "critico", "alto", "medio", "machine learning", "score"
        ]):
            msg = (
                "### 🧠 Auditoría Inmutable e IA Local de Detección de Anomalías (CU-20 / CU-22)\n\n"
                "El módulo de auditoría protege la integridad operacional de Bóveda mediante dos pilares:\n\n"
                "1. **Cadena Hash Inmutable (CU-20):**\n"
                "   - Cada acción en el sistema (logins, MFA, creación de bóvedas, accesos, descargas) genera un evento inmutable enlazado con el hash SHA-256 del evento previo (`hash_anterior` -> `hash_evento`).\n"
                "   - Si alguien intentara alterar la base de datos, la cadena se rompe y el sistema lo detecta de inmediato.\n\n"
                "2. **IA Local de Anomalías - Isolation Forest (CU-22):**\n"
                "   - **100% On-Premise y Privado:** Se ejecuta en CPU local usando Scikit-Learn; ningún dato sale a nubes externas.\n"
                "   - **Cómo usarlo:** En la pestaña **Auditoría**, presiona el botón **'IA Local de Anomalías (CU-22)'**.\n"
                "   - **Criterios de Riesgo:**\n"
                "     - 🔴 **CRÍTICO (`score < -0.10`):** Desviación estadística severa (por ejemplo, múltiples fallos consecutivos de MFA en horas de madrugada).\n"
                "     - 🟠 **ALTO (`-0.10 <= score < -0.05`):** Acceso desde terminales u horarios poco comunes.\n"
                "     - 🟡 **MEDIO / NORMAL:** Comportamiento estadístico habitual de la organización."
            )
            actions = [
                AssistantAction(
                    label="Ver Auditoría e IA Local",
                    action_type="navigate",
                    target="/audit",
                    icon="ShieldAlert",
                ),
            ]
            follow_ups = [
                "¿Cómo se calculan los scores de anomalía?",
                "¿Qué características evalúa el modelo Isolation Forest?",
                "¿Cómo veo el detalle de un evento de auditoría específico?",
            ]
            return "AUDITORIA_IA", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 5. SEGURIDAD, MFA / TOTP Y POLÍTICAS (CU-01 / CU-02 / CU-03)
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "mfa", "doble factor", "totp", "autenticador", "google authenticator",
            "inactividad", "bloqueo", "politica", "contrasena", "seguridad",
            "cu01", "cu02", "cu03", "tiempo"
        ]):
            msg = (
                "### 🛡️ Seguridad de Acceso: MFA y Políticas de Sesión\n\n"
                "1. **Activar Doble Factor de Autenticación (MFA TOTP):**\n"
                "   - En el **Panel Principal**, haz clic en el botón **'Configurar MFA'**.\n"
                "   - Escanea el código QR en pantalla con **Google Authenticator**, **Microsoft Authenticator** o **Authy**.\n"
                "   - Ingresa el código de 6 dígitos para verificar y activar el segundo factor en tu cuenta.\n"
                "2. **Bloqueo por Inactividad:**\n"
                "   - Si te alejas de tu computadora, la sesión se bloqueará automáticamente según el temporizador configurado (ej. 5 o 15 minutos).\n"
                "   - Para reanudar tu trabajo, solo debes introducir tu contraseña en el modal de desbloqueo.\n"
                "3. **Políticas de Seguridad:**\n"
                "   - Haz clic en **'Políticas de Seguridad'** en el Panel para ajustar la longitud mínima de contraseñas, complejidad y políticas de sesión."
            )
            actions = [
                AssistantAction(
                    label="Configurar MFA",
                    action_type="modal",
                    target="mfa_modal",
                    icon="QrCode",
                ),
                AssistantAction(
                    label="Políticas de Seguridad",
                    action_type="modal",
                    target="security_policies",
                    icon="ShieldCheck",
                ),
                AssistantAction(
                    label="Ir al Panel",
                    action_type="navigate",
                    target="/dashboard",
                    icon="LayoutDashboard",
                ),
            ]
            follow_ups = [
                "¿Qué hago si pierdo mi teléfono con el autenticador MFA?",
                "¿Cómo cambio el tiempo de bloqueo por inactividad?",
                "¿Cómo autorizo este equipo como dispositivo de confianza?",
            ]
            return "SEGURIDAD_MFA", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 6. BÓVEDAS & CIFRADO DE ARCHIVOS (CU-06 / CU-08 / CU-10)
        # -------------------------------------------------------------
        if any(w in norm for w in [
            "boveda", "crear boveda", "desbloquear", "archivo", "subir archivo",
            "descargar", "cifrar", "descifrar", "aes", "pbkdf2", "cu06", "cu-06",
            "cu08", "cu-08", "cu10", "cu-10", "clave maestra"
        ]):
            if any(w in norm for w in ["subir", "cargar", "guardar archivo", "cifrar archivo"]):
                msg = (
                    "### 📁 Cómo subir y cifrar archivos en tu Bóveda (CU-08 / CU-10)\n\n"
                    "En Bóveda Híbrida los archivos **se cifran en tu navegador antes de enviarse al servidor**:\n\n"
                    "1. **Accede a Bóvedas:** Dirígete a la sección **Bóvedas** en el menú superior.\n"
                    "2. **Desbloquea la Bóveda:** Si la bóveda está bloqueada, haz clic en **'Desbloquear'** e ingresa tu contraseña maestra local.\n"
                    "3. **Sube tu archivo:** Dentro de la bóveda desbloqueada, usa el botón **'Subir Archivo Cifrado'** o arrastra el documento a la zona indicada.\n"
                    "4. **Cifrado AES-256-GCM:** Tu navegador generará una clave aleatoria de 256 bits, cifrará el contenido localmente, "
                    "calculará el hash SHA-256 para validación de integridad y envolverá la clave con la clave de tu bóveda.\n"
                    "5. **Almacenamiento Seguro:** Solo el texto cifrado (*ciphertext*) viaja a la nube/almacenamiento MinIO. El servidor jamás conoce el contenido."
                )
            elif any(w in norm for w in ["descargar", "bajar", "abrir archivo", "descifrar"]):
                msg = (
                    "### 📥 Cómo descargar y descifrar archivos de tu Bóveda\n\n"
                    "1. **Asegúrate de tener la bóveda desbloqueada** con tu contraseña maestra en la página de **Bóvedas**.\n"
                    "2. **Selecciona el archivo:** En la lista de documentos cifrados, haz clic en el botón de **'Descargar'**.\n"
                    "3. **Verificación de Integridad:** El navegador descarga el *ciphertext*, calcula su hash SHA-256 y verifica que coincida exactamente con el registrado.\n"
                    "4. **Descifrado en Memoria:** Desenvuelve la clave AES-256-GCM del archivo usando la clave maestra activa en tu memoria local y genera el archivo original limpio para guardarlo en tu computadora."
                )
            elif any(w in norm for w in ["desbloquear", "abrir boveda", "contrasena maestra"]):
                msg = (
                    "### 🔓 Cómo desbloquear una Bóveda\n\n"
                    "1. Dirígete a la pestaña **Bóvedas**.\n"
                    "2. Haz clic en el botón **'Desbloquear Bóveda'** en la tarjeta correspondiente.\n"
                    "3. Ingresa la **contraseña maestra** que asignaste al crearla.\n"
                    "4. El navegador derivará la clave de cifrado local mediante **PBKDF2/Argon2**, desencriptará el sobre del dispositivo y mantendrá la clave activa en memoria segura durante tu sesión.\n"
                    "*(Nota: La contraseña maestra nunca se envía al servidor ni se guarda en base de datos)*."
                )
            else:
                msg = (
                    "### 🔐 Cómo crear y utilizar una Bóveda Segura (CU-06)\n\n"
                    "1. **Crear Bóveda:** En la sección **Bóvedas**, presiona **'+ Nueva Bóveda'**.\n"
                    "2. **Definir Nombre y Contraseña Maestra:** Asigna un nombre, descripción y una contraseña maestra robusta.\n"
                    "3. **Generación de Claves Cero Conocimiento:** Tu navegador genera una clave de bóveda aleatoria de 256 bits, "
                    "la envuelve con tu contraseña y además la asocia criptográficamente a tu dispositivo confiable actual.\n"
                    "4. **Listo para Usar:** Una vez creada, puedes desbloquearla para subir archivos sensibles, notas, credenciales y compartirlos de forma delegada."
                )

            actions = [
                AssistantAction(
                    label="Ir a Bóvedas",
                    action_type="navigate",
                    target="/vaults",
                    icon="Lock",
                ),
                AssistantAction(
                    label="Crear Nueva Bóveda",
                    action_type="modal",
                    target="create_vault",
                    icon="PlusCircle",
                ),
            ]
            follow_ups = [
                "¿Cómo subo un archivo cifrado?",
                "¿Cómo comparto una bóveda con un compañero?",
                "¿Qué hago si olvido la contraseña maestra de mi bóveda?",
            ]
            return "BOVEDAS", msg, actions, follow_ups

        # -------------------------------------------------------------
        # 7. RESPUESTA GENERAL / BIENVENIDA / MENÚ DE AYUDA
        # -------------------------------------------------------------
        msg = (
            f"### 👋 ¡Hola{f', {user.nombre.split()[0]}' if user and user.nombre else ''}! Soy el Asistente Inteligente de Bóveda Híbrida.\n\n"
            "Estoy aquí para guiarte en el uso de la plataforma con máxima seguridad y privacidad. "
            "Puedo explicarte paso a paso cómo realizar cualquier tarea en el sistema:\n\n"
            "* 🔐 **Bóvedas & Cifrado:** Cómo crear bóvedas, desbloquearlas y cifrar/descifrar archivos en tu equipo.\n"
            "* 💻 **Dispositivos de Confianza (CU-04 / CU-05):** Cómo autorizar tu computadora mediante firma criptográfica Ed25519 y gestionar terminales.\n"
            "* 🆘 **Recuperación de Emergencia (CU-12):** Cómo generar y usar tu kit de rescate si olvidas la contraseña.\n"
            "* 👥 **Compartición Segura (CU-17):** Cómo compartir bóvedas con compañeros manteniendo Cero Conocimiento.\n"
            "* 🧠 **Auditoría e IA Local (CU-20 / CU-22):** Cómo consultar la bitácora inmutable y detectar anomalías con Machine Learning local.\n"
            "* 🛡️ **Seguridad y MFA:** Cómo activar el doble factor de autenticación (Google Authenticator) y configurar políticas.\n\n"
            "**¿Qué te gustaría hacer o aprender ahora?** Haz clic en una acción rápida o escribe tu consulta en el campo inferior."
        )
        actions = [
            AssistantAction(
                label="Ir a Bóvedas",
                action_type="navigate",
                target="/vaults",
                icon="Lock",
            ),
            AssistantAction(
                label="Dispositivos de Confianza",
                action_type="modal",
                target="trusted_devices",
                icon="Laptop",
            ),
            AssistantAction(
                label="Auditoría e IA",
                action_type="navigate",
                target="/audit",
                icon="Brain",
            ),
            AssistantAction(
                label="Configurar MFA",
                action_type="modal",
                target="mfa_modal",
                icon="ShieldCheck",
            ),
        ]
        follow_ups = [
            "¿Cómo creo mi primera bóveda?",
            "¿Cómo autorizo mi equipo como de confianza?",
            "¿Cómo funciona la IA de detección de anomalías?",
            "¿Cómo activo el doble factor (MFA)?",
        ]
        return "GENERAL", msg, actions, follow_ups
