-- Supabase SQL: profiles table + signup trigger + RLS
-- Source of truth: user_input_ref (2026-01-28)
-- Intended to run in Supabase SQL editor (auth.users exists, auth.uid() available)

begin;

-- 1) profiles table
do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type public.user_role as enum ('customer', 'technician', 'admin');
  end if;
end
$$;

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role public.user_role not null default 'customer',
  full_name text,
  created_at timestamptz not null default now()
);

-- 2) helper: is current user an admin?
-- SECURITY DEFINER so it can read profiles even when RLS is enabled.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles p
    where p.user_id = auth.uid()
      and p.role = 'admin'
  );
$$;

-- 3) RLS
alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own_or_admin" on public.profiles;
create policy "profiles_select_own_or_admin"
on public.profiles
for select
to authenticated
using (
  user_id = auth.uid()
  or public.is_admin()
);

drop policy if exists "profiles_update_own_or_admin" on public.profiles;
create policy "profiles_update_own_or_admin"
on public.profiles
for update
to authenticated
using (
  user_id = auth.uid()
  or public.is_admin()
)
with check (
  user_id = auth.uid()
  or public.is_admin()
);

-- Note: we intentionally do NOT add an INSERT policy for client-side inserts.
-- Profile rows are created automatically via the trigger below.

-- 4) After signup: auto-insert profile row
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (user_id, role, full_name, created_at)
  values (
    new.id,
    'customer',
    coalesce(new.raw_user_meta_data->>'full_name', null),
    now()
  )
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- 5) brands table (booking catalog)
create table if not exists public.brands (
  id uuid primary key default gen_random_uuid(),
  name text unique not null,
  logo_url text,
  created_at timestamptz not null default now()
);

-- RLS: authenticated users can read brands.
alter table public.brands enable row level security;

drop policy if exists "brands_select_authenticated" on public.brands;
create policy "brands_select_authenticated"
on public.brands
for select
to authenticated
using (true);

-- Seed default mobile brands (id auto-generated)
insert into public.brands (name) values ('Samsung') on conflict (name) do nothing;
insert into public.brands (name) values ('Apple') on conflict (name) do nothing;
insert into public.brands (name) values ('Xiaomi') on conflict (name) do nothing;
insert into public.brands (name) values ('OnePlus') on conflict (name) do nothing;
insert into public.brands (name) values ('Vivo') on conflict (name) do nothing;
insert into public.brands (name) values ('Oppo') on conflict (name) do nothing;
insert into public.brands (name) values ('Realme') on conflict (name) do nothing;
insert into public.brands (name) values ('Motorola') on conflict (name) do nothing;
insert into public.brands (name) values ('Nokia') on conflict (name) do nothing;
insert into public.brands (name) values ('Google Pixel') on conflict (name) do nothing;

commit;
