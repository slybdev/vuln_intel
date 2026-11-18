'use client';

import * as React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ChartConfig, ChartContainer, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart';
import { Bar, BarChart, CartesianGrid, XAxis } from 'recharts';

export interface MonthlyAdvisoryDataPoint {
  date: string;
  all: number;
  priority: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  unrated?: number;
}

const chartConfig = {
  advisories: {
    label: 'Advisories',
  },
  all: {
    label: 'All advisories',
    color: 'var(--chart-1, #2563eb)',
  },
  priority: {
    label: 'Critical + High',
    color: 'var(--chart-2, #dc2626)',
  },
} satisfies ChartConfig;

export function MonthlyPublishedAdvisoriesChart({
  data = [],
}: {
  data?: MonthlyAdvisoryDataPoint[];
}) {
  const [activeMetric, setActiveMetric] = React.useState<keyof typeof chartConfig>('all');

  const total = React.useMemo(
    () => ({
      all: data.reduce((acc, curr) => acc + (curr.all || 0), 0),
      priority: data.reduce((acc, curr) => acc + (curr.priority || 0), 0),
    }),
    [data],
  );

  return (
    <Card className="py-0">
      <CardHeader className="flex flex-col items-stretch border-b !p-0 sm:flex-row">
        <div className="flex flex-1 flex-col justify-center gap-1 px-6 pt-4 pb-3 sm:!py-0">
          <CardTitle>Monthly published advisories</CardTitle>
          <CardDescription>New vulnerabilities by original publication month · rolling 12 months</CardDescription>
        </div>
        <div className="flex">
          {(['all', 'priority'] as const).map((key) => (
            <button
              key={key}
              data-active={activeMetric === key}
              className="data-[active=true]:bg-muted/50 relative z-30 flex flex-1 flex-col justify-center gap-1 border-t px-6 py-4 text-left even:border-l sm:border-t-0 sm:border-l sm:px-8 sm:py-6"
              onClick={() => setActiveMetric(key)}
            >
              <span className="text-muted-foreground text-xs">{chartConfig[key].label}</span>
              <span className="text-lg leading-none font-bold sm:text-3xl">
                {total[key].toLocaleString()}
              </span>
            </button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="px-2 sm:p-6">
        <ChartContainer config={chartConfig} className="aspect-auto h-[250px] w-full">
          <BarChart
            accessibilityLayer
            data={data}
            margin={{
              left: 12,
              right: 12,
            }}
          >
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="date"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={32}
              tickFormatter={(value) => {
                const date = new Date(value);
                return isNaN(date.getTime())
                  ? value
                  : date.toLocaleDateString('en-US', {
                      month: 'short',
                      year: '2-digit',
                    });
              }}
            />
            <ChartTooltip
              content={
                <ChartTooltipContent
                  className="w-[180px]"
                  nameKey="advisories"
                  labelFormatter={(value) => {
                    const date = new Date(value);
                    return isNaN(date.getTime())
                      ? value
                      : date.toLocaleDateString('en-US', {
                          month: 'long',
                          year: 'numeric',
                        });
                  }}
                />
              }
            />
            <Bar dataKey={activeMetric} fill={`var(--color-${activeMetric})`} />
          </BarChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

export default MonthlyPublishedAdvisoriesChart;
