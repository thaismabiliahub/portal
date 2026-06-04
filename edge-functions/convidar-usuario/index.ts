// =====================================================================
// AFFECTION PORTAL · FASE 2 · EDGE FUNCTION convidar-usuario
// =====================================================================
// Recebe POST do front com { email, nome } + JWT no Authorization.
// Valida que quem chama é super_admin.
// Gera link de convite via Supabase Auth Admin.
// Manda e-mail HTML elegante via Resend API.
//
// Headers esperados:
//   Authorization: Bearer <jwt do supabase>
//   Content-Type: application/json
//
// Body:
//   { email: "jady@exemplo.com", nome: "Jady" }
//
// Resposta sucesso (200):
//   { status: "ok", message: "Convite enviado" }
//
// Resposta erro (400/401/403/500):
//   { status: "error", message }
// =====================================================================

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const RESEND_API_URL = "https://api.resend.com/emails";
const FROM_EMAIL = "convites@affectionconsultoria.com.br";
const FROM_NAME = "Affection Consultoria";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return jsonResp({ status: "error", message: "Method not allowed", step: "method" }, 200);
  }

  // SEMPRE 200 com status no body. Antes os erros saiam 401/403/500 e o SDK Supabase as
  // vezes nao consegue ler o body — Thais via "Edge Function returned a non-2xx status code"
  // com contexto vazio. Agora ela sempre ve o erro real.
  try {
    // ===== Valida Authorization =====
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return jsonResp({ status: "error", message: "Authorization obrigatório", step: "auth_header" }, 200);
    }

    // ===== Lê env =====
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const resendApiKey = Deno.env.get("RESEND_API_KEY")!;

    if (!resendApiKey) {
      return jsonResp({ status: "error", message: "RESEND_API_KEY nao configurado no Supabase", step: "env" }, 200);
    }
    if (!supabaseServiceKey) {
      return jsonResp({ status: "error", message: "SUPABASE_SERVICE_ROLE_KEY nao configurado", step: "env" }, 200);
    }

    // ===== Verifica quem chama (JWT) =====
    const supabaseUser = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userError } = await supabaseUser.auth.getUser();
    if (userError || !user) {
      return jsonResp({ status: "error", message: "JWT invalido: " + (userError?.message || "sem user"), step: "jwt" }, 200);
    }

    // ===== Checa permissao em "pessoas" =====
    // Tenta achar quem esta chamando: primeiro por auth_id, depois fallback por email.
    // Se nada existe, deixa passar quem tem email batendo com THAIS_EMAIL (master hardcoded
    // pra nao ficar travada sem conseguir convidar ninguem).
    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
    let usuario: any = null;
    let infoBusca = "";
    // Tentativa 1: por auth_id
    try {
      const r1 = await supabaseAdmin
        .from("pessoas")
        .select("id, nivel, sistema, status, email, auth_id")
        .eq("auth_id", user.id)
        .maybeSingle();
      if (r1.data) { usuario = r1.data; infoBusca = "encontrado por auth_id"; }
      else if (r1.error) infoBusca = "auth_id falhou: " + r1.error.message;
      else infoBusca = "auth_id nao achou";
    } catch (e: any) {
      infoBusca = "auth_id excecao: " + (e?.message || e);
    }
    // Tentativa 2: por email do JWT
    if (!usuario && user.email) {
      try {
        const r2 = await supabaseAdmin
          .from("pessoas")
          .select("id, nivel, sistema, status, email, auth_id")
          .eq("email", user.email)
          .maybeSingle();
        if (r2.data) {
          usuario = r2.data;
          infoBusca += " | encontrado por email";
          // Aproveita pra vincular auth_id se estiver vazio
          if (!usuario.auth_id) {
            await supabaseAdmin.from("pessoas").update({ auth_id: user.id }).eq("id", usuario.id);
          }
        } else if (r2.error) {
          infoBusca += " | email falhou: " + r2.error.message;
        } else {
          infoBusca += " | email nao achou";
        }
      } catch (e: any) {
        infoBusca += " | email excecao: " + (e?.message || e);
      }
    }
    // Fallback de seguranca: emails master conhecidos sempre podem convidar
    const MASTER_EMAILS = ["thaismabilia@gmail.com", "thaismabiliaia@gmail.com", "manusaffection@gmail.com"];
    const ehMaster = user.email && MASTER_EMAILS.includes(user.email.toLowerCase());

    if (!usuario && !ehMaster) {
      return jsonResp({
        status: "error",
        message: "Quem chama nao foi encontrado em pessoas. Busca: " + infoBusca + ". Email JWT: " + (user.email || "?"),
        step: "permission_lookup"
      }, 200);
    }
    if (usuario && (usuario.status === "removido" || usuario.status === "suspenso")) {
      return jsonResp({ status: "error", message: "Usuario " + usuario.status + " nao pode convidar", step: "permission_status" }, 200);
    }
    if (usuario && !usuario.sistema && usuario.nivel !== "admin" && !ehMaster) {
      return jsonResp({
        status: "error",
        message: "Apenas admin pode convidar. Seu nivel: " + (usuario.nivel || "?") + ", sistema: " + (usuario.sistema || false),
        step: "permission_level"
      }, 200);
    }

    // ===== Lê body =====
    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResp({ status: "error", message: "Body JSON invalido", step: "body" }, 200);
    }

    const { email, nome } = body;
    if (!email || !nome) {
      return jsonResp({ status: "error", message: "Body deve conter { email, nome }", step: "body" }, 200);
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return jsonResp({ status: "error", message: "E-mail invalido", step: "body" }, 200);
    }

    // ===== Gera link de convite via Supabase Auth Admin =====
    const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
      type: "invite",
      email: email,
      options: {
        redirectTo: "https://portal.affectionconsultoria.com.br/",
      },
    });

    if (linkError) {
      // Se usuário já existe, generateLink pode falhar — tenta magic link
      if (linkError.message?.includes("already") || linkError.message?.includes("registered")) {
        const { data: magicData, error: magicError } = await supabaseAdmin.auth.admin.generateLink({
          type: "magiclink",
          email: email,
          options: { redirectTo: "https://portal.affectionconsultoria.com.br/" },
        });
        if (magicError) {
          return jsonResp({ status: "error", message: "Erro ao gerar magic link: " + magicError.message, step: "generate_link_magic" }, 200);
        }
        linkData.properties = magicData.properties;
        if (magicData.user) linkData.user = magicData.user;
      } else {
        return jsonResp({ status: "error", message: "Erro ao gerar link: " + linkError.message, step: "generate_link" }, 200);
      }
    }

    const inviteLink = linkData?.properties?.action_link;
    if (!inviteLink) {
      return jsonResp({ status: "error", message: "Link de convite nao foi gerado", step: "generate_link" }, 200);
    }

    // ===== Vincula auth_id na linha de "pessoas" (amarra os dois lados) =====
    // generateLink cria/encontra o usuario em auth.users e retorna em linkData.user.
    // Sem essa vinculacao a linha de "pessoas" fica com auth_id NULL — o usuario loga
    // no Auth mas o sistema nao acha o registro dele em pessoas (e tudo fica vazio).
    const authUserId = linkData?.user?.id;
    if (authUserId) {
      const { error: linkPessoaErr } = await supabaseAdmin
        .from("pessoas")
        .update({ auth_id: authUserId })
        .eq("email", email)
        .is("auth_id", null);
      if (linkPessoaErr) {
        console.warn("Falha ao vincular auth_id em pessoas:", linkPessoaErr.message);
        // Nao bloqueia o envio — usuario ainda pode logar, so precisa vincular depois.
      }
    }

    // ===== Monta HTML do e-mail (marca Affection) =====
    const htmlEmail = montarHtmlConvite(nome, inviteLink);
    const textoEmail = `Olá ${nome},\n\nVocê foi convidada(o) por Thais Mabilia pra acessar o Affection Portal.\n\nClique no link pra criar sua senha e entrar:\n${inviteLink}\n\nSe você não esperava esse convite, ignore este e-mail.\n\n— Affection Consultoria`;

    // ===== Envia via Resend API =====
    const resendResponse = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `${FROM_NAME} <${FROM_EMAIL}>`,
        to: [email],
        subject: `${nome}, você foi convidada pra Affection Portal`,
        html: htmlEmail,
        text: textoEmail,
      }),
    });

    const resendData = await resendResponse.json();

    if (!resendResponse.ok) {
      console.error("Resend error:", resendData);
      return jsonResp({
        status: "error",
        message: "Resend rejeitou: " + (resendData?.message || resendData?.name || resendResponse.statusText) +
                 (resendData?.statusCode ? " (status " + resendData.statusCode + ")" : ""),
        step: "resend_send",
        resendDetail: resendData
      }, 200);
    }

    return jsonResp({
      status: "ok",
      message: `Convite enviado para ${email}`,
      resend_id: resendData?.id || null,
    }, 200);

  } catch (err) {
    console.error("Erro inesperado:", err);
    return jsonResp({
      status: "error",
      message: "Excecao: " + (err instanceof Error ? err.message : String(err)),
      step: "exception",
      stack: err instanceof Error ? err.stack?.slice(0, 800) : undefined
    }, 200);
  }
});

// =====================================================================
// HELPERS
// =====================================================================

function jsonResp(payload: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function montarHtmlConvite(nome: string, link: string): string {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Convite Affection Portal</title>
</head>
<body style="margin:0;padding:0;background:#faf8f6;font-family:'Helvetica Neue',Arial,sans-serif;color:#1a1a18;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#faf8f6;padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #ebe5df;">
          <tr>
            <td style="padding:32px 36px 24px;background:linear-gradient(135deg,#532137,#6a2a47);color:white;">
              <div style="font-family:'Georgia',serif;font-size:24px;font-weight:600;letter-spacing:-0.01em;">Affection Consultoria</div>
              <div style="font-size:12px;opacity:0.8;margin-top:6px;text-transform:uppercase;letter-spacing:0.12em;">Convite de acesso</div>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 36px 24px;">
              <div style="font-family:'Georgia',serif;font-size:20px;font-weight:600;margin-bottom:16px;color:#1a1a18;">Olá, ${escapeHtml(nome)}</div>
              <p style="font-size:14px;line-height:1.6;color:#3a3a37;margin:0 0 14px 0;">
                Você foi convidada por <strong>Thais Mabilia</strong> pra acessar o Affection Portal.
              </p>
              <p style="font-size:14px;line-height:1.6;color:#3a3a37;margin:0 0 28px 0;">
                Clique no botão abaixo pra criar sua senha e entrar no sistema:
              </p>
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;">
                <tr>
                  <td style="background:#532137;border-radius:8px;">
                    <a href="${link}" style="display:inline-block;padding:14px 32px;color:white;text-decoration:none;font-size:14px;font-weight:600;">Aceitar convite e entrar</a>
                  </td>
                </tr>
              </table>
              <p style="font-size:12px;line-height:1.6;color:#6b6660;margin:32px 0 0 0;text-align:center;">
                Se o botão não funcionar, copia e cola este link no navegador:<br>
                <a href="${link}" style="color:#532137;word-break:break-all;">${link}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 36px;background:#faf8f6;border-top:1px solid #ebe5df;">
              <p style="font-size:11px;line-height:1.5;color:#9a948c;margin:0;">
                Se você não esperava este convite, ignore este e-mail. Nenhuma ação é necessária.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 36px;background:#2c2c2a;color:#c8c2bb;font-size:11px;text-align:center;">
              Affection Consultoria · affectionconsultoria.com.br
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
