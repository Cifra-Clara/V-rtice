-- =====================================================================
-- Cifra Clara · reforço de segurança do banco (Supabase)
-- Rode no Supabase → SQL Editor. O script pode ser executado mais de uma vez.
-- Ele NÃO apaga dados nem remove políticas existentes: só acrescenta proteções.
-- Leia os avisos (NOTICE) no fim da execução.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Diagnóstico: tabelas do schema public sem RLS (Row Level Security)
--    Toda tabela acessada pelo site precisa de RLS ligado, senão a chave
--    pública (anon) do site permite ler os dados de todos os clientes.
-- ---------------------------------------------------------------------
select c.relname as tabela, c.relrowsecurity as rls_ligado,
       (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname) as politicas
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by c.relrowsecurity, c.relname;

-- ---------------------------------------------------------------------
-- 1. Liga o RLS nas tabelas do site que já têm políticas.
--    Tabela sem nenhuma política fica como está e gera um aviso:
--    ligar o RLS nela sem política bloquearia o site inteiro.
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array['contas','empresas','eventos','solicitacoes','admins','config'] loop
    if to_regclass('public.'||t) is null then continue; end if;
    if exists (select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname=t and c.relrowsecurity) then continue; end if;
    if exists (select 1 from pg_policies where schemaname='public' and tablename=t) then
      execute format('alter table public.%I enable row level security', t);
      raise notice 'RLS ligado em public.%', t;
    else
      raise notice 'ATENÇÃO: public.% está SEM RLS e SEM políticas. Crie as políticas antes de ligar o RLS.', t;
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 2. Quem é administrador (função auxiliar, lê a tabela admins ignorando o RLS)
-- ---------------------------------------------------------------------
create or replace function public.cc_is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins a where lower(a.email) = lower(coalesce(auth.jwt()->>'email','')));
$$;
revoke all on function public.cc_is_admin() from public;
grant execute on function public.cc_is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- 3. Verificação em duas etapas obrigatória para quem a ativou.
--    Política RESTRITIVA: soma-se às existentes. Quem tem fator TOTP verificado
--    só lê e grava com sessão "aal2" (senha + código). Quem não ativou segue normal.
-- ---------------------------------------------------------------------
do $$
declare t text;
  cond text := '((select auth.jwt()->>''aal'') = ''aal2'' or not exists (select 1 from auth.mfa_factors f where f.user_id = (select auth.uid()) and f.status = ''verified''))';
begin
  foreach t in array array['contas','empresas','eventos','admins'] loop
    if to_regclass('public.'||t) is null then continue; end if;
    if not exists (select 1 from pg_policies where schemaname='public' and tablename=t and policyname='cc_mfa_quando_ativado') then
      execute format('create policy cc_mfa_quando_ativado on public.%I as restrictive for all to authenticated using %s with check %s', t, cond, cond);
      raise notice 'MFA obrigatório (quando ativado) em public.%', t;
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 4. Campos que só o administrador (ou as funções do servidor) pode mudar.
--    Impede que um cliente, pela API, se dê um plano, se desbloqueie
--    ou libere o próprio painel. Funções SECURITY DEFINER (ex.: confirmar_pagamento)
--    continuam funcionando, porque rodam com o papel do dono da função.
-- ---------------------------------------------------------------------
create or replace function public.cc_sem_pend(x jsonb) returns jsonb language sql immutable as $$
  select case when jsonb_typeof(x) = 'object' then x - 'pend' else x end;
$$;

create or replace function public.cc_protege_contas() returns trigger
language plpgsql set search_path = public as $$
declare o jsonb := to_jsonb(old); n jsonb := to_jsonb(new); k text;
begin
  if current_user not in ('authenticated','anon') or public.cc_is_admin() then return new; end if;
  foreach k in array array['id','email','status','obs','criado'] loop
    if (o ? k) and (o->k) is distinct from (n->k) then raise exception 'SEM_PERMISSAO'; end if;
  end loop;
  -- o cliente só pode registrar um pedido pendente (campo "pend"); o resto do plano é da equipe
  if (o ? 'plano') and public.cc_sem_pend(o->'plano') is distinct from public.cc_sem_pend(n->'plano') then raise exception 'SEM_PERMISSAO'; end if;
  return new;
end $$;

create or replace function public.cc_protege_empresas() returns trigger
language plpgsql set search_path = public as $$
declare o jsonb := to_jsonb(old); n jsonb := to_jsonb(new); k text;
begin
  if current_user not in ('authenticated','anon') or public.cc_is_admin() then return new; end if;
  foreach k in array array['id','owner','liberado','liberado_em','bloqueado'] loop
    if (o ? k) and (o->k) is distinct from (n->k) then raise exception 'SEM_PERMISSAO'; end if;
  end loop;
  return new;
end $$;

do $$
begin
  if to_regclass('public.contas') is not null then
    drop trigger if exists cc_protege_contas on public.contas;
    create trigger cc_protege_contas before update on public.contas for each row execute function public.cc_protege_contas();
  end if;
  if to_regclass('public.empresas') is not null then
    drop trigger if exists cc_protege_empresas on public.empresas;
    create trigger cc_protege_empresas before update on public.empresas for each row execute function public.cc_protege_empresas();
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 5. Cada cliente lê o próprio registro de atividade (tela Segurança).
--    Só cria a política se a tabela tiver a coluna "conta".
-- ---------------------------------------------------------------------
do $$
begin
  if to_regclass('public.eventos') is not null
     and exists (select 1 from information_schema.columns where table_schema='public' and table_name='eventos' and column_name='conta')
     and not exists (select 1 from pg_policies where schemaname='public' and tablename='eventos' and policyname='cc_le_proprios_eventos') then
    create policy cc_le_proprios_eventos on public.eventos for select to authenticated using (conta::text = (select auth.uid())::text);
    raise notice 'Clientes agora leem os próprios eventos.';
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 6. Conferência: políticas de cada tabela (revise especialmente "admins":
--    um cliente comum não deve conseguir listar os e-mails de administradores).
-- ---------------------------------------------------------------------
select tablename, policyname, permissive, roles, cmd
from pg_policies where schemaname = 'public' order by tablename, policyname;

-- =====================================================================
-- Ajustes no painel do Supabase (não são feitos por SQL):
--  • Authentication → Sign In / Providers → Email: "Confirm email" ligado;
--    tamanho mínimo da senha 10; "Leaked password protection" ligado (plano Pro).
--  • Authentication → Multi-Factor: TOTP habilitado (vem ligado por padrão).
--  • Authentication → URL Configuration: Site URL = https://usarcifraclara.com.br
--    e só os endereços oficiais em "Redirect URLs".
--  • Authentication → Sessions (plano Pro): "Inactivity timeout" de 30 minutos,
--    para o limite valer também no servidor.
--  • Authentication → Rate Limits: mantenha os limites de login e e-mail baixos.
--  • Hospedagem: sirva o site só por HTTPS ("Enforce HTTPS" no GitHub Pages).
-- =====================================================================
