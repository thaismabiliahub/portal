// AFFECTION PORTAL - convidar-usuario (JS puro, sem TS, pra evitar boot error)
// Cria usuario em auth.users + envia email built-in do Supabase, vincula auth_id
// em pessoas. SEMPRE retorna 200 com {status, message, step} no body.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function jsonResp(payload, status) {
  return new Response(JSON.stringify(payload), {
    status: status || 200,
    headers: Object.assign({}, corsHeaders, { "Content-Type": "application/json" }),
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return jsonResp({ status: "error", message: "Method not allowed", step: "method" }, 200);
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return jsonResp({ status: "error", message: "Authorization obrigatorio", step: "auth_header" }, 200);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseServiceKey) {
      return jsonResp({ status: "error", message: "SUPABASE_SERVICE_ROLE_KEY ausente", step: "env" }, 200);
    }

    const supabaseUser = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const userResp = await supabaseUser.auth.getUser();
    const user = userResp.data && userResp.data.user;
    if (userResp.error || !user) {
      return jsonResp({
        status: "error",
        message: "JWT invalido: " + ((userResp.error && userResp.error.message) || "sem user"),
        step: "jwt"
      }, 200);
    }

    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

    let usuario = null;
    let infoBusca = "";
    try {
      const r1 = await supabaseAdmin
        .from("pessoas")
        .select("id, nivel, sistema, status, email, auth_id")
        .eq("auth_id", user.id)
        .maybeSingle();
      if (r1.data) { usuario = r1.data; infoBusca = "auth_id"; }
      else if (r1.error) infoBusca = "auth_id err: " + r1.error.message;
      else infoBusca = "auth_id nao achou";
    } catch (e) {
      infoBusca = "auth_id exc: " + ((e && e.message) || String(e));
    }

    if (!usuario && user.email) {
      try {
        const r2 = await supabaseAdmin
          .from("pessoas")
          .select("id, nivel, sistema, status, email, auth_id")
          .eq("email", user.email)
          .maybeSingle();
        if (r2.data) {
          usuario = r2.data;
          infoBusca += " | email";
          if (!usuario.auth_id) {
            await supabaseAdmin.from("pessoas").update({ auth_id: user.id }).eq("id", usuario.id);
          }
        } else if (r2.error) infoBusca += " | email err: " + r2.error.message;
        else infoBusca += " | email nao achou";
      } catch (e) {
        infoBusca += " | email exc: " + ((e && e.message) || String(e));
      }
    }

    const MASTER_EMAILS = ["thaismabilia@gmail.com", "thaismabiliaia@gmail.com", "manusaffection@gmail.com"];
    const ehMaster = !!(user.email && MASTER_EMAILS.indexOf(user.email.toLowerCase()) >= 0);

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

    let body;
    try { body = await req.json(); } catch (e) {
      return jsonResp({ status: "error", message: "Body JSON invalido", step: "body" }, 200);
    }
    const email = body && body.email;
    const nome = body && body.nome;
    if (!email || !nome) {
      return jsonResp({ status: "error", message: "Body deve conter { email, nome }", step: "body" }, 200);
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return jsonResp({ status: "error", message: "E-mail invalido", step: "body" }, 200);
    }

    // Convida via Supabase Auth (cria em auth.users + envia email built-in)
    const inviteResp = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
      data: { nome: nome },
      redirectTo: "https://portal.affectionconsultoria.com.br/",
    });
    const inviteData = inviteResp.data;
    const inviteError = inviteResp.error;
    let authUserId = inviteData && inviteData.user && inviteData.user.id;

    if (inviteError) {
      const msg = inviteError.message || "";
      if (msg.indexOf("already") >= 0 || msg.indexOf("registered") >= 0 || msg.indexOf("exists") >= 0) {
        const linkResp = await supabaseAdmin.auth.admin.generateLink({
          type: "magiclink",
          email: email,
          options: { redirectTo: "https://portal.affectionconsultoria.com.br/" },
        });
        if (linkResp.error) {
          return jsonResp({
            status: "error",
            message: "Usuario ja existe e magic link falhou: " + linkResp.error.message,
            step: "magic_link"
          }, 200);
        }
        authUserId = linkResp.data && linkResp.data.user && linkResp.data.user.id;
        if (authUserId) {
          await supabaseAdmin.from("pessoas").update({ auth_id: authUserId }).eq("email", email).is("auth_id", null);
        }
        return jsonResp({
          status: "ok",
          message: email + " ja estava no Auth — link de acesso gerado abaixo (copie e envie):",
          actionLink: (linkResp.data && linkResp.data.properties && linkResp.data.properties.action_link) || null,
          alreadyExisted: true
        }, 200);
      }
      return jsonResp({ status: "error", message: "Erro ao convidar: " + msg, step: "invite" }, 200);
    }

    if (authUserId) {
      try {
        await supabaseAdmin.from("pessoas").update({ auth_id: authUserId }).eq("email", email).is("auth_id", null);
      } catch (e) {
        console.warn("Falha ao vincular auth_id:", (e && e.message) || e);
      }
    }

    return jsonResp({
      status: "ok",
      message: "Convite enviado pra " + email + " (Supabase Auth)",
      authUserId: authUserId,
    }, 200);

  } catch (err) {
    console.error("Excecao:", err);
    return jsonResp({
      status: "error",
      message: "Excecao: " + ((err && err.message) || String(err)),
      step: "exception",
      stack: (err && err.stack) ? String(err.stack).slice(0, 800) : undefined
    }, 200);
  }
});
