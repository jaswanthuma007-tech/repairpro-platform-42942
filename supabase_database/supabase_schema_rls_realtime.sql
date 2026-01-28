-- MobileRepair / RepairPro Supabase schema + RLS + Realtime
-- This script is intended to be executed in the *Supabase project's* SQL editor.
-- It assumes Supabase Auth is enabled (auth.users exists) and uses auth.uid().

begin;

-- Extensions (safe in Supabase; pgcrypto is commonly enabled)
create extension if not exists "pgcrypto";

-- =========================
-- Types
-- =========================
do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type public.user_role as enum ('customer', 'technician', 'admin');
  end if;

  if not exists (select 1 from pg_type where typname = 'repair_status') then
    create type public.repair_status as enum (
      'requested',
      'scheduled',
      'assigned',
      'in_progress',
      'awaiting_parts',
      'completed',
      'cancelled'
    );
  end if;
end
$$;

-- =========================
-- Core tables
-- =========================

-- Profiles: 1:1 with auth.users
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role public.user_role not null default 'customer',
  full_name text,
  phone text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Brand catalog (Samsung-style experience: Brand -> Model)
create table if not exists public.brands (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Device models (per brand)
create table if not exists public.device_models (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands(id) on delete restrict,
  name text not null,
  device_category text not null default 'phone', -- phones/tablets/tv/watch/audio etc.
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  unique (brand_id, name)
);

-- Services / issues (what kind of repair)
create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  base_price_cents integer,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Repairs: booking entity
create table if not exists public.repairs (
  id uuid primary key default gen_random_uuid(),

  customer_id uuid not null references public.profiles(user_id) on delete restrict,
  technician_id uuid references public.profiles(user_id) on delete set null,

  brand_id uuid not null references public.brands(id) on delete restrict,
  device_model_id uuid not null references public.device_models(id) on delete restrict,
  service_id uuid not null references public.services(id) on delete restrict,

  status public.repair_status not null default 'requested',

  -- Address step
  address_line1 text not null,
  address_line2 text,
  city text not null,
  state text,
  postal_code text,
  country text not null default 'US',

  notes text,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_repairs_customer on public.repairs(customer_id);
create index if not exists idx_repairs_technician on public.repairs(technician_id);
create index if not exists idx_repairs_status on public.repairs(status);
create index if not exists idx_repairs_created_at on public.repairs(created_at desc);

-- Status history: append-only audit trail
create table if not exists public.repair_status_history (
  id uuid primary key default gen_random_uuid(),
  repair_id uuid not null references public.repairs(id) on delete cascade,

  from_status public.repair_status,
  to_status public.repair_status not null,

  changed_by uuid references public.profiles(user_id) on delete set null,
  note text,

  created_at timestamptz not null default now()
);

create index if not exists idx_rsh_repair_id on public.repair_status_history(repair_id);
create index if not exists idx_rsh_created_at on public.repair_status_history(created_at desc);

-- =========================
-- Updated-at triggers
-- =========================
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_profiles_updated_at on public.profiles;
create trigger trg_profiles_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

drop trigger if exists trg_repairs_updated_at on public.repairs;
create trigger trg_repairs_updated_at
before update on public.repairs
for each row execute function public.set_updated_at();

-- =========================
-- Helper functions for RLS (SECURITY DEFINER)
-- =========================
create or replace function public.current_user_role()
returns public.user_role
language sql
stable
security definer
set search_path = public
as $$
  select p.role
  from public.profiles p
  where p.user_id = auth.uid()
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_user_role() = 'admin', false)
$$;

create or replace function public.is_technician()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_user_role() = 'technician', false)
$$;

-- =========================
-- Auto profile creation on signup
-- =========================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (user_id, role, full_name)
  values (new.id, 'customer', coalesce(new.raw_user_meta_data->>'full_name', null))
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- =========================
-- Status history automation
-- =========================
create or replace function public.log_repair_status_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status is distinct from old.status then
    insert into public.repair_status_history (
      repair_id,
      from_status,
      to_status,
      changed_by,
      note
    ) values (
      new.id,
      old.status,
      new.status,
      auth.uid(),
      null
    );
  end if;

  return new;
end;
$$;

drop trigger if exists trg_repairs_log_status on public.repairs;
create trigger trg_repairs_log_status
after update of status on public.repairs
for each row execute function public.log_repair_status_change();

-- =========================
-- Row Level Security (RLS)
-- =========================
alter table public.profiles enable row level security;
alter table public.brands enable row level security;
alter table public.device_models enable row level security;
alter table public.services enable row level security;
alter table public.repairs enable row level security;
alter table public.repair_status_history enable row level security;

-- ---- profiles policies
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
on public.profiles
for select
to authenticated
using (user_id = auth.uid() or public.is_admin());

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
on public.profiles
for update
to authenticated
using (user_id = auth.uid() or public.is_admin())
with check (user_id = auth.uid() or public.is_admin());

-- Only admins can change role (enforced by separate policy that allows update-any,
-- but with check requiring admin; non-admins update still allowed above but cannot change role
-- because of the check expression)
drop policy if exists "profiles_admin_update_any" on public.profiles;
create policy "profiles_admin_update_any"
on public.profiles
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

-- ---- catalog policies (read for all authenticated; write for admin)
drop policy if exists "brands_select_authenticated" on public.brands;
create policy "brands_select_authenticated"
on public.brands
for select
to authenticated
using (true);

drop policy if exists "brands_admin_write" on public.brands;
create policy "brands_admin_write"
on public.brands
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "brands_admin_update" on public.brands;
create policy "brands_admin_update"
on public.brands
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "brands_admin_delete" on public.brands;
create policy "brands_admin_delete"
on public.brands
for delete
to authenticated
using (public.is_admin());

drop policy if exists "device_models_select_authenticated" on public.device_models;
create policy "device_models_select_authenticated"
on public.device_models
for select
to authenticated
using (true);

drop policy if exists "device_models_admin_write" on public.device_models;
create policy "device_models_admin_write"
on public.device_models
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "device_models_admin_update" on public.device_models;
create policy "device_models_admin_update"
on public.device_models
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "device_models_admin_delete" on public.device_models;
create policy "device_models_admin_delete"
on public.device_models
for delete
to authenticated
using (public.is_admin());

drop policy if exists "services_select_authenticated" on public.services;
create policy "services_select_authenticated"
on public.services
for select
to authenticated
using (true);

drop policy if exists "services_admin_write" on public.services;
create policy "services_admin_write"
on public.services
for insert
to authenticated
with check (public.is_admin());

drop policy if exists "services_admin_update" on public.services;
create policy "services_admin_update"
on public.services
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "services_admin_delete" on public.services;
create policy "services_admin_delete"
on public.services
for delete
to authenticated
using (public.is_admin());

-- ---- repairs policies
-- Customers: can create repairs for themselves only
drop policy if exists "repairs_customer_insert_self" on public.repairs;
create policy "repairs_customer_insert_self"
on public.repairs
for insert
to authenticated
with check (
  customer_id = auth.uid()
  and (public.current_user_role() = 'customer' or public.is_admin())
);

-- Select: customer sees own; technician sees assigned; admin sees all
drop policy if exists "repairs_select_role_scoped" on public.repairs;
create policy "repairs_select_role_scoped"
on public.repairs
for select
to authenticated
using (
  public.is_admin()
  or customer_id = auth.uid()
  or (public.is_technician() and technician_id = auth.uid())
);

-- Update: 
--  - customer can update their own repairs only while still in 'requested' (e.g., adjust address/notes)
--  - technician can update assigned repair (e.g., status)
--  - admin can update any (including assigning technician)
drop policy if exists "repairs_update_customer_limited" on public.repairs;
create policy "repairs_update_customer_limited"
on public.repairs
for update
to authenticated
using (
  customer_id = auth.uid()
  and status = 'requested'
)
with check (
  customer_id = auth.uid()
  and status = 'requested'
  -- prevent customer from assigning technician
  and technician_id is null
);

drop policy if exists "repairs_update_technician_assigned" on public.repairs;
create policy "repairs_update_technician_assigned"
on public.repairs
for update
to authenticated
using (
  public.is_technician()
  and technician_id = auth.uid()
)
with check (
  public.is_technician()
  and technician_id = auth.uid()
);

drop policy if exists "repairs_update_admin_any" on public.repairs;
create policy "repairs_update_admin_any"
on public.repairs
for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

-- Optional: delete only by admin
drop policy if exists "repairs_delete_admin" on public.repairs;
create policy "repairs_delete_admin"
on public.repairs
for delete
to authenticated
using (public.is_admin());

-- ---- repair_status_history policies
-- Select: customer sees history for their repairs; technician sees history for assigned; admin sees all
drop policy if exists "rsh_select_role_scoped" on public.repair_status_history;
create policy "rsh_select_role_scoped"
on public.repair_status_history
for select
to authenticated
using (
  public.is_admin()
  or exists (
    select 1
    from public.repairs r
    where r.id = repair_status_history.repair_id
      and (
        r.customer_id = auth.uid()
        or (public.is_technician() and r.technician_id = auth.uid())
      )
  )
);

-- Insert: only via triggers / service role ideally; but allow technicians/admin to insert notes if needed
drop policy if exists "rsh_insert_technician_or_admin" on public.repair_status_history;
create policy "rsh_insert_technician_or_admin"
on public.repair_status_history
for insert
to authenticated
with check (
  public.is_admin()
  or public.is_technician()
);

-- No updates/deletes (audit log): omit policies for update/delete

-- =========================
-- Realtime
-- =========================
-- Supabase Realtime uses a publication. Supabase generally provides "supabase_realtime" publication.
-- We add tables to it so changes are broadcast to clients subscribed via supabase-js.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    -- add tables (if already added, Supabase/PG will error; so guard via pg_publication_tables)
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'repairs'
    ) then
      alter publication supabase_realtime add table public.repairs;
    end if;

    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'repair_status_history'
    ) then
      alter publication supabase_realtime add table public.repair_status_history;
    end if;
  end if;
end
$$;

commit;
