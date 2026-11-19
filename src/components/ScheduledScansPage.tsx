import { useEffect, useMemo, useState } from "react";
import {
  CalendarClock,
  CalendarDays,
  Check,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Plus,
  Radar,
  ShieldCheck,
} from "lucide-react";
import { DayPicker } from "react-day-picker";
import { cn } from "@/src/lib/utils";
import { apiFetch, FeedUpdateSchedule } from "@/src/lib/vuln-intel-api";
import {
  Badge,
  Button,
  buttonVariants,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/src/components/ui/primitives";

interface ScheduledUpdate {
  id: string;
  title: string;
  date: Date;
  time: string;
  target: string;
  cadence: string;
  status: string;
}

const DEFAULT_TIME = "02:00";
const FEED_SOURCES = "OSV · NVD · GHSA · CISA KEV · EPSS";

function formatDateKey(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(
    2,
    "0"
  )}-${String(date.getDate()).padStart(2, "0")}`;
}

function dateFromKey(value: string) {
  const [year, month, day] = value.slice(0, 10).split("-").map(Number);
  return new Date(year, month - 1, day);
}

function scheduleDates(schedule: FeedUpdateSchedule | null) {
  if (!schedule?.enabled || !schedule.next_run_at) return [];
  const firstDate = dateFromKey(schedule.next_run_at);
  const dates = Array.from({ length: 42 }, (_, index) => {
    const date = new Date(firstDate);
    date.setDate(firstDate.getDate() + index);
    return date;
  });
  if (schedule.last_run_at) {
    dates.push(dateFromKey(schedule.last_run_at));
  }
  return dates;
}

function formatLongDate(date: Date) {
  return date.toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function formatRunDate(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(value));
}

export default function ScheduledScansPage() {
  const [schedule, setSchedule] = useState<FeedUpdateSchedule | null>(null);
  const [selectedDate, setSelectedDate] = useState<Date>(() => new Date());
  const [calendarView, setCalendarView] = useState<"month" | "week">("month");
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [runTime, setRunTime] = useState(DEFAULT_TIME);
  const [toastMessage, setToastMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    apiFetch<{ schedule: FeedUpdateSchedule | null }>("/api/feed-schedule")
      .then(({ schedule: currentSchedule }) => {
        if (!active) return;
        setSchedule(currentSchedule);
        if (currentSchedule) setRunTime(currentSchedule.time);
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(
            reason instanceof Error
              ? reason.message
              : "Feed schedule could not be loaded."
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const scheduledDates = useMemo(() => scheduleDates(schedule), [schedule]);
  const nextRunDate = schedule?.next_run_at
    ? dateFromKey(schedule.next_run_at)
    : null;
  const lastRunDate = schedule?.last_run_at
    ? dateFromKey(schedule.last_run_at)
    : null;
  const selectedDateKey = formatDateKey(selectedDate);
  const hasScheduledUpdate =
    schedule?.enabled &&
    ((nextRunDate && selectedDateKey >= formatDateKey(nextRunDate)) ||
      (lastRunDate && selectedDateKey === formatDateKey(lastRunDate)));
  const dayUpdates: ScheduledUpdate[] = hasScheduledUpdate && schedule
    ? [{
        id: "external-feed-update",
        title: "External OSINT feed refresh",
        date: selectedDate,
        time: schedule.time,
        target: FEED_SOURCES,
        cadence: "Daily",
        status:
          lastRunDate && selectedDateKey === formatDateKey(lastRunDate)
            ? schedule.last_run_status ?? "Completed"
            : "Scheduled",
      }]
    : [];
  const upcomingUpdates: ScheduledUpdate[] =
    schedule?.enabled && nextRunDate
      ? Array.from({ length: 4 }, (_, index) => {
          const date = new Date(nextRunDate);
          date.setDate(nextRunDate.getDate() + index);
          return {
            id: `external-feed-update-${formatDateKey(date)}`,
            title: "External OSINT feed refresh",
            date,
            time: schedule.time,
            target: FEED_SOURCES,
            cadence: "Daily",
            status: "Scheduled",
          };
        })
      : [];

  const weekDays = useMemo(() => {
    const start = new Date(selectedDate);
    start.setDate(selectedDate.getDate() - selectedDate.getDay());
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(start);
      d.setDate(start.getDate() + i);
      return d;
    });
  }, [selectedDate]);

  const weekRangeLabel = `${weekDays[0].toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  })} – ${weekDays[6].toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  })}`;

  function openNewScanForm() {
    setRunTime(schedule?.time ?? DEFAULT_TIME);
    setIsFormOpen(true);
    setToastMessage("");
    setError("");
  }

  async function handleSaveSchedule(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const response = await apiFetch<{ schedule: FeedUpdateSchedule }>(
        "/api/feed-schedule",
        {
          method: "PUT",
          body: JSON.stringify({ enabled: true, time: runTime }),
        }
      );
      setSchedule(response.schedule);
      if (response.schedule.next_run_at) {
        setSelectedDate(dateFromKey(response.schedule.next_run_at));
      }
      setIsFormOpen(false);
      setToastMessage("Daily feed update schedule saved.");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Feed schedule could not be saved."
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1500px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            Security operations · automation
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Scheduled feed updates
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Keep external vulnerability intelligence current with a daily refresh.
          </p>
        </div>
        <Button
          onClick={openNewScanForm}
          className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
        >
          <Plus className="size-4" />
          {schedule?.enabled ? "Edit daily schedule" : "Schedule daily update"}
        </Button>
      </div>

      <section
        className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"
        aria-label="Feed update schedule summary"
      >
        {[
          {
            title: "Schedule",
            value: loading ? "…" : schedule?.enabled ? "ACTIVE" : "NOT SET",
            detail: "daily external feed refresh",
            icon: CalendarClock,
            tone: "bg-orange-400/10 text-orange-300",
          },
          {
            title: "Next update",
            value: schedule?.enabled ? schedule.time : "—",
            detail: schedule?.enabled
              ? `${formatRunDate(schedule.next_run_at)} · UTC`
              : "choose a daily run time",
            icon: Clock3,
            tone: "bg-amber-300/10 text-amber-200",
          },
          {
            title: "External sources",
            value: "05",
            detail: "OSV · NVD · GHSA · KEV · EPSS",
            icon: Radar,
            tone: "bg-sky-300/10 text-sky-200",
          },
          {
            title: "Last run",
            value: schedule?.last_run_status?.toUpperCase() ?? "—",
            detail: schedule?.last_run_at
              ? formatRunDate(schedule.last_run_at)
              : "no scheduled refresh yet",
            icon: ShieldCheck,
            tone:
              schedule?.last_run_status === "failed"
                ? "bg-red-300/10 text-red-200"
                : "bg-emerald-300/10 text-emerald-200",
          },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <Card key={item.title} className="siem-card">
              <CardContent className="flex items-start justify-between p-4 sm:p-5">
                <div>
                  <p className="text-[11px] font-medium uppercase tracking-[.14em] text-muted-foreground">
                    {item.title}
                  </p>
                  <div className="mt-3 font-mono text-3xl font-semibold tracking-tight text-foreground tabular-nums">
                    {item.value}
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {item.detail}
                  </p>
                </div>
                <span className={`rounded-md p-2 ${item.tone}`}>
                  <Icon className="size-4" />
                </span>
              </CardContent>
            </Card>
          );
        })}
      </section>
      {error && (
        <div
          role="alert"
          className="rounded-md border border-red-400/20 bg-red-400/5 px-4 py-3 text-xs text-red-200"
        >
          {error}
        </div>
      )}
      {schedule?.last_run_error && (
        <div
          role="alert"
          className="rounded-md border border-amber-400/20 bg-amber-400/5 px-4 py-3 text-xs text-amber-200"
        >
          {schedule.last_run_error}
        </div>
      )}

      <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(340px,1fr)]">
        <Card className="siem-card min-w-0">
          <CardHeader className="flex-col gap-3 pb-2 sm:flex-row sm:items-center sm:justify-between sm:space-y-0">
            <div>
              <CardTitle className="text-sm">Feed update calendar</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                Daily external feed collection · times shown in UTC
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Badge
                variant="outline"
                className="border-orange-400/20 bg-orange-400/5 text-orange-300"
              >
                <span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-orange-400" />
                {schedule?.enabled ? "Daily · 5 feeds" : "Not scheduled"}
              </Badge>
              <div
                role="group"
                aria-label="Calendar view"
                className="flex items-center gap-1 rounded-md border border-border/70 p-0.5"
              >
                <button
                  type="button"
                  aria-label="Month view"
                  aria-pressed={calendarView === "month"}
                  onClick={() => setCalendarView("month")}
                  className={cn(
                    "inline-flex h-7 items-center gap-1.5 rounded px-2 text-[10px] font-medium transition-colors cursor-pointer",
                    calendarView === "month"
                      ? "border border-orange-400/30 bg-orange-400/10 text-orange-200"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  <CalendarDays className="size-3" />
                  Month
                </button>
                <button
                  type="button"
                  aria-label="Week view"
                  aria-pressed={calendarView === "week"}
                  onClick={() => setCalendarView("week")}
                  className={cn(
                    "inline-flex h-7 items-center gap-1.5 rounded px-2 text-[10px] font-medium transition-colors cursor-pointer",
                    calendarView === "week"
                      ? "border border-orange-400/30 bg-orange-400/10 text-orange-200"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  <CalendarClock className="size-3" />
                  Week
                </button>
              </div>
            </div>
          </CardHeader>

          <CardContent className="flex justify-center px-3 pb-5 pt-2 sm:px-6">
            {calendarView === "month" ? (
              <DayPicker
                mode="single"
                selected={selectedDate}
                onSelect={(d) => d && setSelectedDate(d)}
                defaultMonth={selectedDate}
                showOutsideDays
                modifiers={{ scheduled: scheduledDates }}
                modifiersClassNames={{
                  scheduled:
                    "after:absolute after:bottom-1 after:left-1/2 after:size-1 after:-translate-x-1/2 after:rounded-full after:bg-orange-400 after:animate-pulse after:shadow-[0_0_8px_rgba(251,146,60,0.8)]",
                }}
                className="w-full max-w-[560px] rounded-lg border border-border/70 bg-transparent p-3 [--cell-size:2.75rem] sm:[--cell-size:3.5rem]"
                classNames={{
                  root: "w-full",
                  months: "flex flex-col relative w-full",
                  month: "flex flex-col w-full gap-4",
                  nav: "flex items-center gap-1 w-full absolute top-0 inset-x-0 justify-between z-10",
                  button_previous: cn(
                    buttonVariants({ variant: "ghost" }),
                    "size-9 p-0 select-none text-muted-foreground hover:text-foreground"
                  ),
                  button_next: cn(
                    buttonVariants({ variant: "ghost" }),
                    "size-9 p-0 select-none text-muted-foreground hover:text-foreground"
                  ),
                  month_caption:
                    "flex items-center justify-center h-9 w-full px-9",
                  caption_label: "select-none font-medium text-sm",
                  month_grid: "w-full border-collapse",
                  weekdays: "grid grid-cols-7",
                  weekday:
                    "text-muted-foreground rounded-md font-normal text-[0.8rem] select-none text-center py-1",
                  week: "grid grid-cols-7 w-full mt-2 gap-1",
                  day: "relative w-full p-0 text-center aspect-square select-none flex items-center justify-center",
                  day_button:
                    "relative flex size-full items-center justify-center rounded-md text-xs font-normal transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer",
                  selected:
                    "[&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:font-semibold",
                  today: "[&>button]:bg-accent/20 [&>button]:text-orange-200",
                  outside: "text-muted-foreground/50",
                  disabled: "text-muted-foreground opacity-50",
                }}
                components={{
                  Chevron: ({ orientation }) =>
                    orientation === "left" ? (
                      <ChevronLeft className="size-4" />
                    ) : (
                      <ChevronRight className="size-4" />
                    ),
                }}
              />
            ) : (
              <div className="w-full max-w-[560px] rounded-lg border border-border/70 bg-background/20 p-3 sm:p-4">
                <div className="mb-4 flex items-center justify-between">
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Previous week"
                    onClick={() => {
                      const prev = new Date(selectedDate);
                      prev.setDate(prev.getDate() - 7);
                      setSelectedDate(prev);
                    }}
                    className="size-8 text-muted-foreground hover:text-orange-300"
                  >
                    <ChevronLeft className="size-4" />
                  </Button>
                  <div className="text-center">
                    <p className="text-sm font-medium">{weekRangeLabel}</p>
                    <p className="mt-0.5 text-[9px] uppercase tracking-[.16em] text-muted-foreground">
                      Weekly view · UTC
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Next week"
                    onClick={() => {
                      const next = new Date(selectedDate);
                      next.setDate(next.getDate() + 7);
                      setSelectedDate(next);
                    }}
                    className="size-8 text-muted-foreground hover:text-orange-300"
                  >
                    <ChevronRight className="size-4" />
                  </Button>
                </div>

                <div className="grid grid-cols-7 gap-1.5 sm:gap-2">
                  {weekDays.map((day) => {
                    const hasScan = scheduledDates.some(
                      (d) => formatDateKey(d) === formatDateKey(day)
                    );
                    const isSelected =
                      formatDateKey(day) === formatDateKey(selectedDate);
                    return (
                      <button
                        key={formatDateKey(day)}
                        type="button"
                        aria-label={formatLongDate(day)}
                        aria-pressed={isSelected}
                        onClick={() => setSelectedDate(day)}
                        className={cn(
                          "relative flex min-h-16 flex-col items-center justify-center gap-2 rounded-md border px-1 py-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-300 sm:min-h-20 cursor-pointer",
                          isSelected
                            ? "border-orange-400/40 bg-orange-400/10 text-orange-200"
                            : "border-transparent text-muted-foreground hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <span className="text-[9px] uppercase tracking-wide sm:text-[10px]">
                          {day.toLocaleDateString("en-US", {
                            weekday: "short",
                          })}
                        </span>
                        <span
                          className={cn(
                            "font-mono text-sm tabular-nums",
                            isSelected ? "font-semibold" : "text-foreground"
                          )}
                        >
                          {day.getDate()}
                        </span>
                        {hasScan && (
                          <span
                            aria-hidden="true"
                            className="size-1.5 animate-pulse rounded-full bg-orange-400 shadow-[0_0_8px_rgba(251,146,60,0.8)]"
                          />
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </CardContent>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border/70 px-5 py-3 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-2">
              <span className="size-1.5 rounded-full bg-orange-400" />
              Daily feed refresh
            </span>
            <span className="flex items-center gap-2">
              <span className="size-2.5 rounded-sm bg-primary" />
              Selected day
            </span>
            <span className="ml-auto hidden font-mono uppercase tracking-wider sm:block">
              All times UTC
            </span>
          </div>
        </Card>

        <div className="flex min-w-0 flex-col gap-4">
          {isFormOpen && (
            <Card className="siem-card border-orange-400/20">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Daily feed refresh</CardTitle>
                <p className="text-xs text-muted-foreground">
                  Collect and normalize the latest data from all configured
                  vulnerability sources.
                </p>
              </CardHeader>
              <CardContent className="pt-0">
                <form
                  onSubmit={handleSaveSchedule}
                  className="flex flex-col gap-4"
                >
                  <div className="flex flex-col gap-3">
                    <div className="flex flex-col gap-1.5">
                      <label
                        htmlFor="feed-run-time"
                        className="text-xs text-muted-foreground"
                      >
                        Run every day at (UTC)
                      </label>
                      <input
                        id="feed-run-time"
                        type="time"
                        value={runTime}
                        onChange={(e) => setRunTime(e.target.value)}
                        required
                        className="h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      />
                    </div>
                    <div className="rounded-md border border-border/70 bg-background/40 p-3">
                      <p className="text-[10px] font-medium uppercase tracking-[.14em] text-muted-foreground">
                        Daily sources
                      </p>
                      <p className="mt-1 text-xs leading-relaxed text-foreground">
                        {FEED_SOURCES}
                      </p>
                    </div>
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setIsFormOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      size="sm"
                      disabled={saving}
                      className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                    >
                      <Check className="size-4" />
                      {saving ? "Saving…" : "Save daily schedule"}
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          )}

          <Card className="siem-card min-w-0 flex-1">
            <CardHeader className="flex-row items-start justify-between space-y-0 pb-3">
              <div>
                <CardTitle className="text-sm">
                  {selectedDate.toDateString() ===
                  new Date().toDateString()
                    ? "Today’s feed update"
                    : "Scheduled activity"}
                </CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  {formatLongDate(selectedDate)}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Set daily feed update time"
                onClick={openNewScanForm}
                className="size-8 text-orange-300 hover:bg-orange-400/10"
              >
                <Plus className="size-4" />
              </Button>
            </CardHeader>

            <CardContent className="flex flex-col gap-3 pt-0">
              {dayUpdates.length > 0 ? (
                dayUpdates.map((update) => (
                  <article
                    key={update.id}
                    className="rounded-lg border border-border/70 bg-background/40 p-3.5 transition-colors hover:border-orange-400/20"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 gap-3">
                        <span className="mt-0.5 rounded-md bg-orange-400/10 p-2 text-orange-300">
                          <Radar className="size-4" />
                        </span>
                        <div className="min-w-0">
                          <h3 className="truncate text-xs font-medium text-foreground">
                            {update.title}
                          </h3>
                          <p className="mt-1 truncate text-[10px] text-muted-foreground">
                            {update.target}
                          </p>
                        </div>
                      </div>
                      <Badge
                        variant="outline"
                        className="shrink-0 border-orange-400/20 bg-orange-400/5 text-[9px] text-orange-300"
                      >
                        {update.status}
                      </Badge>
                    </div>
                    <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-2.5 text-[10px] text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-mono">
                        <Clock3 className="size-3" />
                        {update.time} UTC
                      </span>
                      <span>{update.cadence}</span>
                    </div>
                  </article>
                ))
              ) : (
                <div className="flex min-h-40 flex-col items-center justify-center rounded-lg border border-dashed border-border/80 px-5 text-center">
                  <span className="mb-3 rounded-full bg-muted p-3 text-muted-foreground">
                    <CalendarDays className="size-5" />
                  </span>
                  <h3 className="text-sm font-medium text-foreground">
                    {loading ? "Loading schedule…" : "No daily update scheduled"}
                  </h3>
                  <p className="mt-1 max-w-[230px] text-xs leading-relaxed text-muted-foreground">
                    {schedule?.enabled
                      ? "There is no feed refresh planned for this day."
                      : "Set a daily time to pull and normalize the latest external vulnerability data."}
                  </p>
                  <Button
                    onClick={openNewScanForm}
                    variant="outline"
                    size="sm"
                    className="mt-4 border-orange-400/20 text-orange-300 hover:bg-orange-400/10"
                  >
                    Schedule daily update
                    <ChevronRight className="size-4" />
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="siem-card">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Coming up next</CardTitle>
              <p className="text-xs text-muted-foreground">
                Upcoming daily external feed refreshes
              </p>
            </CardHeader>
            <CardContent className="flex flex-col gap-3 pt-0">
              {upcomingUpdates.map((update) => (
                <button
                  key={update.id}
                  type="button"
                  onClick={() => setSelectedDate(update.date)}
                  className="flex w-full items-center gap-3 rounded-md p-2 text-left transition-colors hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-300 cursor-pointer"
                >
                  <span className="flex size-9 shrink-0 flex-col items-center justify-center rounded-md border border-border/70 bg-background/60 font-mono">
                    <span className="text-[8px] uppercase text-muted-foreground">
                      {update.date.toLocaleDateString("en-US", {
                        month: "short",
                      })}
                    </span>
                    <span className="text-xs font-semibold text-foreground tabular-nums">
                      {update.date.getDate()}
                    </span>
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-foreground">
                      {update.title}
                    </span>
                    <span className="mt-1 block text-[10px] text-muted-foreground">
                      {update.time} UTC · {update.cadence}
                    </span>
                  </span>
                  <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
                </button>
              ))}
              {!schedule?.enabled && !loading && (
                <p className="rounded-md border border-dashed border-border/80 px-3 py-4 text-center text-xs text-muted-foreground">
                  Configure a daily schedule to see upcoming feed updates.
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </section>

      {toastMessage && (
        <div
          role="status"
          className="fixed bottom-5 right-5 z-40 rounded-lg border border-emerald-400/20 bg-card px-4 py-3 text-xs text-emerald-200 shadow-xl"
        >
          <span className="mr-2 inline-flex size-4 items-center justify-center rounded-full bg-emerald-400/10">
            <Check className="size-3" />
          </span>
          {toastMessage}
        </div>
      )}
    </main>
  );
}
