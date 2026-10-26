-- ARTIST TEAM SPACE — schema v1
-- Run in Supabase SQL Editor as project owner.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'master' check (role in ('master','senior','admin')),
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, display_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)), 'master')
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_manager()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles where id=auth.uid() and role in ('admin','senior')); $$;
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin'); $$;

create table if not exists public.salary_rates (
  id uuid primary key default gen_random_uuid(),
  category text not null unique,
  mode text not null default 'fixed' check (mode in ('fixed','percent')),
  payout numeric(12,2) not null default 0 check (payout >= 0),
  check_amount numeric(12,2) not null default 0 check (check_amount >= 0),
  updated_at timestamptz not null default now()
);
insert into public.salary_rates(category,mode,payout) values
 ('VIP','fixed',150),('Partner','fixed',150),('Ambassador','fixed',150),
 ('Staff','fixed',150),('Business','fixed',120),('Prem','percent',10),('Cocktail','percent',10)
on conflict(category) do nothing;

create table if not exists public.receipt_entries (
  id uuid primary key default gen_random_uuid(),
  master_id uuid not null references public.profiles(id),
  category text not null,
  quantity integer not null default 1 check (quantity > 0),
  check_amount numeric(12,2) not null default 0 check (check_amount >= 0),
  work_date date not null default current_date,
  note text,
  created_at timestamptz not null default now(),
  created_by uuid not null default auth.uid() references public.profiles(id)
);

create table if not exists public.shifts (
  id uuid primary key default gen_random_uuid(),
  master_id uuid not null references public.profiles(id),
  shift_date date not null,
  starts_at time not null,
  ends_at time not null,
  note text,
  created_at timestamptz not null default now(),
  created_by uuid not null default auth.uid() references public.profiles(id)
);

create table if not exists public.shift_swap_requests (
  id uuid primary key default gen_random_uuid(),
  shift_id uuid not null references public.shifts(id) on delete cascade,
  requester_id uuid not null references public.profiles(id),
  note text,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.inventory_items (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  unit text not null default 'шт',
  expected_qty numeric(12,3) not null default 0,
  active boolean not null default true,
  created_by uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists public.inventory_counts (
  id uuid primary key default gen_random_uuid(),
  item_id uuid not null references public.inventory_items(id),
  actual_qty numeric(12,3) not null check (actual_qty >= 0),
  expected_qty numeric(12,3) not null default 0,
  counted_by uuid not null default auth.uid() references public.profiles(id),
  count_date date not null default current_date,
  note text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.salary_rates enable row level security;
alter table public.receipt_entries enable row level security;
alter table public.shifts enable row level security;
alter table public.shift_swap_requests enable row level security;
alter table public.inventory_items enable row level security;
alter table public.inventory_counts enable row level security;

-- Profiles: staff see team names; only admins change roles.
drop policy if exists "profiles_select_authenticated" on public.profiles;
create policy "profiles_select_authenticated" on public.profiles for select to authenticated using (true);
drop policy if exists "profiles_update_self_or_admin" on public.profiles;
create policy "profiles_update_self_or_admin" on public.profiles for update to authenticated
using (id=auth.uid() or public.is_admin())
with check ((id=auth.uid() and role=(select p.role from public.profiles p where p.id=auth.uid())) or public.is_admin());

-- Salary rates are readable by signed-in staff; only managers modify.
drop policy if exists "rates_read" on public.salary_rates;
create policy "rates_read" on public.salary_rates for select to authenticated using (true);
drop policy if exists "rates_manage" on public.salary_rates;
create policy "rates_manage" on public.salary_rates for all to authenticated using (public.is_manager()) with check (public.is_manager());

-- Masters see and create their own receipts; managers can review all.
drop policy if exists "receipts_read" on public.receipt_entries;
create policy "receipts_read" on public.receipt_entries for select to authenticated using (master_id=auth.uid() or public.is_manager());
drop policy if exists "receipts_insert" on public.receipt_entries;
create policy "receipts_insert" on public.receipt_entries for insert to authenticated with check (master_id=auth.uid());
drop policy if exists "receipts_update" on public.receipt_entries;
create policy "receipts_update" on public.receipt_entries for update to authenticated using (master_id=auth.uid() or public.is_manager()) with check (master_id=auth.uid() or public.is_manager());
drop policy if exists "receipts_delete" on public.receipt_entries;
create policy "receipts_delete" on public.receipt_entries for delete to authenticated using (public.is_manager());

-- Schedule is shared; only managers create/change/delete shifts.
drop policy if exists "shifts_read" on public.shifts;
create policy "shifts_read" on public.shifts for select to authenticated using (true);
drop policy if exists "shifts_insert" on public.shifts;
create policy "shifts_insert" on public.shifts for insert to authenticated with check (master_id=auth.uid() or public.is_manager());
drop policy if exists "shifts_update" on public.shifts;
create policy "shifts_update" on public.shifts for update to authenticated using (public.is_manager()) with check (public.is_manager());
drop policy if exists "shifts_delete" on public.shifts;
create policy "shifts_delete" on public.shifts for delete to authenticated using (public.is_manager());

-- Swap requests: requester can read/create own; managers can review all.
drop policy if exists "swaps_read" on public.shift_swap_requests;
create policy "swaps_read" on public.shift_swap_requests for select to authenticated using (requester_id=auth.uid() or public.is_manager());
drop policy if exists "swaps_insert" on public.shift_swap_requests;
create policy "swaps_insert" on public.shift_swap_requests for insert to authenticated with check (requester_id=auth.uid() and status='pending');
drop policy if exists "swaps_review" on public.shift_swap_requests;
create policy "swaps_review" on public.shift_swap_requests for update to authenticated using (public.is_manager()) with check (public.is_manager());

-- Inventory visible to team; item creation and count entry available to signed-in staff.
drop policy if exists "inventory_items_read" on public.inventory_items;
create policy "inventory_items_read" on public.inventory_items for select to authenticated using (true);
drop policy if exists "inventory_items_insert" on public.inventory_items;
create policy "inventory_items_insert" on public.inventory_items for insert to authenticated with check (auth.uid() is not null);
drop policy if exists "inventory_items_update" on public.inventory_items;
create policy "inventory_items_update" on public.inventory_items for update to authenticated using (public.is_manager()) with check (public.is_manager());
drop policy if exists "inventory_counts_read" on public.inventory_counts;
create policy "inventory_counts_read" on public.inventory_counts for select to authenticated using (true);
drop policy if exists "inventory_counts_insert" on public.inventory_counts;
create policy "inventory_counts_insert" on public.inventory_counts for insert to authenticated with check (counted_by=auth.uid());
drop policy if exists "inventory_counts_update" on public.inventory_counts;
create policy "inventory_counts_update" on public.inventory_counts for update to authenticated using (public.is_manager()) with check (public.is_manager());
drop policy if exists "inventory_counts_delete" on public.inventory_counts;
create policy "inventory_counts_delete" on public.inventory_counts for delete to authenticated using (public.is_manager());

-- IMPORTANT: after creating your own account, promote your account to admin:
-- update public.profiles set role='admin' where id=(select id from auth.users where email='YOUR_EMAIL');
